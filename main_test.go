package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(GinkgoWriter)
}

const BOSH_TIMEOUT = 45 * time.Minute
const GoZipFile = "go1.7.1.windows-amd64.zip"
const GolangURL = "https://storage.googleapis.com/golang/" + GoZipFile

type ManifestProperties struct {
	DeploymentName string
	ReleaseName    string
	AZ             string
	VmType         string
	VmExtensions   string
	Network        string
	StemcellOS     string
}

type Config struct {
	Bosh struct {
		CaCert       string `json:"ca_cert"`
		Client       string `json:"client"`
		ClientSecret string `json:"client_secret"`
		Target       string `json:"target"`
		GwPrivateKey string `json:"gw_private_key"`
		GwUser       string `json:"gw_user"`
	} `json:"bosh"`
	StemcellPath         string `json:"stemcell_path"`
	WindowsUtilitiesPath string `json:"windows_utilities_path"`
	StemcellOS           string `json:"stemcell_os"`
	Az                   string `json:"az"`
	VmType               string `json:"vm_type"`
	VmExtensions         string `json:"vm_extensions"`
	Network              string `json:"network"`
}

func NewConfig() (*Config, error) {
	configFilePath := os.Getenv("CONFIG_JSON")
	if configFilePath == "" {
		return nil, fmt.Errorf("invalid config file path: %v", configFilePath)
	}
	body, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("empty config file path: %v", configFilePath)
	}
	var config Config
	err = json.Unmarshal(body, &config)
	if err != nil {
		return nil, fmt.Errorf("unable to parse config file: %v", body)
	}
	return &config, nil
}

func (c *Config) generateManifest(deploymentName string) ([]byte, error) {
	manifestProperties := ManifestProperties{
		DeploymentName: deploymentName,
		ReleaseName:    "wuts-release",
		AZ:             c.Az,
		VmType:         c.VmType,
		VmExtensions:   c.VmExtensions,
		Network:        c.Network,
		StemcellOS:     c.StemcellOS,
	}
	templ, err := template.New("").Parse(manifestTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = templ.Execute(&buf, manifestProperties)
	return buf.Bytes(), err
}

type SSHManifestProperties struct {
	ManifestProperties
	SSHEnabled bool
}

func (c *Config) generateManifestSSH(deploymentName string, enabled bool) ([]byte, error) {
	manifestProperties := SSHManifestProperties{
		ManifestProperties: ManifestProperties{
			DeploymentName: deploymentName,
			ReleaseName:    "wuts-release",
			AZ:             c.Az,
			VmType:         c.VmType,
			VmExtensions:   c.VmExtensions,
			Network:        c.Network,
			StemcellOS:     c.StemcellOS,
		},
		SSHEnabled: enabled,
	}
	templ, err := template.New("").Parse(sshTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = templ.Execute(&buf, manifestProperties)
	return buf.Bytes(), err
}

type RDPManifestProperties struct {
	ManifestProperties
	RDPEnabled bool
}

func (c *Config) generateManifestRDP(deploymentName string, enabled bool) ([]byte, error) {
	manifestProperties := RDPManifestProperties{
		ManifestProperties: ManifestProperties{
			DeploymentName: deploymentName,
			ReleaseName:    "wuts-release",
			AZ:             c.Az,
			VmType:         c.VmType,
			VmExtensions:   c.VmExtensions,
			Network:        c.Network,
			StemcellOS:     c.StemcellOS,
		},
		RDPEnabled: enabled,
	}
	templ, err := template.New("").Parse(rdpTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = templ.Execute(&buf, manifestProperties)
	return buf.Bytes(), err
}

type BoshCommand struct {
	DirectorIP       string
	Client           string
	ClientSecret     string
	CertPath         string // Path to CA CERT file, if any
	Timeout          time.Duration
	GwPrivateKeyPath string // Path to key file
	GwUser           string
}

func NewBoshCommand(config *Config, CertPath string, GwPrivateKeyPath string, duration time.Duration) *BoshCommand {
	return &BoshCommand{
		DirectorIP:       config.Bosh.Target,
		Client:           config.Bosh.Client,
		ClientSecret:     config.Bosh.ClientSecret,
		CertPath:         CertPath,
		Timeout:          duration,
		GwPrivateKeyPath: GwPrivateKeyPath,
		GwUser:           config.Bosh.GwUser,
	}
}

func (c *BoshCommand) args(command string) []string {
	args := strings.Split(command, " ")
	args = append([]string{"-n", "-e", c.DirectorIP, "--client", c.Client, "--client-secret", c.ClientSecret}, args...)
	if c.CertPath != "" {
		args = append([]string{"--ca-cert", c.CertPath}, args...)
	}
	return args
}

func (c *BoshCommand) Run(command string) error {
	cmd := exec.Command("bosh", c.args(command)...)
	log.Printf("\nRUNNING %q\n", strings.Join(cmd.Args, " "))

	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	if err != nil {
		return err
	}
	session.Wait(c.Timeout)

	exitCode := session.ExitCode()
	if exitCode != 0 {
		var stderr []byte
		if session.Err != nil {
			stderr = session.Err.Contents()
		}
		stdout := session.Out.Contents()
		return fmt.Errorf("Non-zero exit code for cmd %q: %d\nSTDERR:\n%s\nSTDOUT:%s\n",
			strings.Join(cmd.Args, " "), exitCode, stderr, stdout)
	}
	return nil
}

func downloadGo() (string, error) {
	dirname, err := ioutil.TempDir("", "")
	if err != nil {
		return "", err
	}

	path := filepath.Join(dirname, GoZipFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return "", err
	}
	defer f.Close()

	res, err := http.Get(GolangURL)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if _, err := io.Copy(f, res.Body); err != nil {
		return "", err
	}

	return path, nil
}

func downloadLogs(jobName string, index int) *gbytes.Buffer {
	tempDir, err := ioutil.TempDir("", "")
	Expect(err).To(Succeed())
	defer os.RemoveAll(tempDir)

	err = bosh.Run(fmt.Sprintf("-d %s logs %s/%d --dir %s", deploymentName, jobName, index, tempDir))
	Expect(err).To(Succeed())

	matches, err := filepath.Glob(filepath.Join(tempDir, fmt.Sprintf("%s.%s.%d-*.tgz", deploymentName, jobName, index)))
	Expect(err).To(Succeed())
	Expect(matches).To(HaveLen(1))

	cmd := exec.Command("tar", "xf", matches[0], "-O", fmt.Sprintf("./%s/%s/job-service-wrapper.out.log", jobName, jobName))
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).To(Succeed())

	return session.Wait().Out
}

var (
	bosh              *BoshCommand
	deploymentName    string
	deploymentNameSSH string
	deploymentNameRDP string
	manifestPath      string
	manifestPathSSH   string
	manifestPathRDP   string
	boshCertPath      string
)

func writeCert(cert string) string {
	if cert != "" {
		certFile, err := ioutil.TempFile("", "")
		Expect(err).To(Succeed())

		_, err = certFile.Write([]byte(cert))
		Expect(err).To(Succeed())

		boshCertPath, err = filepath.Abs(certFile.Name())
		Expect(err).To(Succeed())
		return boshCertPath
	}
	return ""
}

var _ = Describe("Windows Utilities Release", func() {
	var config *Config

	BeforeSuite(func() {
		var err error
		config, err = NewConfig()
		Expect(err).To(Succeed())

		boshCertPath := writeCert(config.Bosh.CaCert)
		boshGwPrivateKeyPath := writeCert(config.Bosh.GwPrivateKey)
		bosh = NewBoshCommand(config, boshCertPath, boshGwPrivateKeyPath, BOSH_TIMEOUT)

		Expect(bosh.Run("login")).To(Succeed())
		deploymentName = fmt.Sprintf("windows-utilities-test-%d", time.Now().UTC().Unix())
		deploymentNameSSH = fmt.Sprintf("windows-utilities-test-ssh-%d", time.Now().UTC().Unix())
		deploymentNameRDP = fmt.Sprintf("windows-utilities-test-rdp-%d", time.Now().UTC().Unix())

		pwd, err := os.Getwd()
		Expect(err).To(Succeed())
		Expect(os.Chdir(filepath.Join(pwd, "assets", "wuts-release"))).To(Succeed()) // push
		defer os.Chdir(pwd)                                                          // pop

		// Generate main manifest
		manifest, err := config.generateManifest(deploymentName)
		Expect(err).To(Succeed())
		manifestFile, err := ioutil.TempFile("", "")
		Expect(err).To(Succeed())
		_, err = manifestFile.Write(manifest)
		Expect(err).To(Succeed())
		manifestPath, err = filepath.Abs(manifestFile.Name())
		Expect(err).To(Succeed())

		// Upload wuts-release from this repository
		Expect(bosh.Run("create-release --force --timestamp-version")).To(Succeed())
		Expect(bosh.Run("upload-release")).To(Succeed())

		// Upload latest windows-utilities release
		matches, err := filepath.Glob(config.WindowsUtilitiesPath)
		Expect(err).To(Succeed(),
			fmt.Sprintf("expected to find windows-utilities at: %s", config.WindowsUtilitiesPath))
		Expect(matches).To(HaveLen(1),
			fmt.Sprintf("expected to find windows-utilities at: %s", config.WindowsUtilitiesPath))

		Expect(bosh.Run(fmt.Sprintf("upload-release %s", matches[0]))).To(Succeed())

		// Upload latest stemcell
		matches, err = filepath.Glob(config.StemcellPath)
		Expect(err).To(Succeed(),
			fmt.Sprintf("expected to find stemcell at: %s", config.StemcellPath))
		Expect(matches).To(HaveLen(1),
			fmt.Sprintf("expected to find stemcell at: %s", config.StemcellPath))

		err = bosh.Run(fmt.Sprintf("upload-stemcell %s", matches[0]))
		if err != nil {
			//AWS takes a while to distribute the AMI across accounts
			time.Sleep(2 * time.Minute)
		}
		Expect(err).To(Succeed())
	})

	It("Enables KMS with Host and custom Port", func() {
		err := bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentName, manifestPath))
		Expect(err).To(Succeed())
		err = bosh.Run(fmt.Sprintf("-d %s run-errand kms-host-enabled", deploymentName))
		Expect(err).To(Succeed())
	})

	It("Does not enable KMS", func() {
		err := bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentName, manifestPath))
		Expect(err).To(Succeed())
		err = bosh.Run(fmt.Sprintf("-d %s run-errand kms-host-not-enabled", deploymentName))
		Expect(err).To(Succeed())
	})

	It("Enables KMS with Host and default Port", func() {
		err := bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentName, manifestPath))
		Expect(err).To(Succeed())
		err = bosh.Run(fmt.Sprintf("-d %s run-errand kms-host-enabled-with-default", deploymentName))
		Expect(err).To(Succeed())
	})

	It("Enables and then disables SSH", func() {
		directorURL, err := url.Parse(bosh.DirectorIP)
		Expect(err).NotTo(HaveOccurred())

		// Generate ssh manifest
		{
			manifest, err := config.generateManifestSSH(deploymentNameSSH, true)
			Expect(err).To(Succeed())

			manifestFile, err := ioutil.TempFile("", "")
			Expect(err).To(Succeed())

			_, err = manifestFile.Write(manifest)
			Expect(err).To(Succeed())
			Expect(manifestFile.Close()).To(Succeed())

			manifestPathSSH, err = filepath.Abs(manifestFile.Name())
			Expect(err).To(Succeed())
		}

		err = bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameSSH, manifestPathSSH))
		Expect(err).To(Succeed())

		// Try to ssh into windows cell
		err = bosh.Run(fmt.Sprintf("-d %s ssh --opts=-T --command=exit check-ssh/0 --gw-user %s --gw-host %s --gw-private-key %s", deploymentNameSSH, bosh.GwUser, directorURL.Hostname(), bosh.GwPrivateKeyPath))
		Expect(err).To(Succeed())

		// Regenerate the manifest
		{
			manifest, err := config.generateManifestSSH(deploymentNameSSH, false)
			Expect(err).To(Succeed())

			err = ioutil.WriteFile(manifestPathSSH, manifest, 0644)
			Expect(err).To(Succeed())
		}

		err = bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameSSH, manifestPathSSH))
		Expect(err).To(Succeed())

		// Try to ssh into windows cell
		err = bosh.Run(fmt.Sprintf("-d %s ssh --opts=-T --command=exit check-ssh/0 --gw-user %s --gw-host %s --gw-private-key %s", deploymentNameSSH, bosh.GwUser, directorURL.Hostname(), bosh.GwPrivateKeyPath))
		Expect(err).NotTo(Succeed())
	})

	It("Enables and then disables RDP", func() {
		// Generate rdp manifest
		{
			manifest, err := config.generateManifestRDP(deploymentNameRDP, true)
			Expect(err).To(Succeed())

			manifestFile, err := ioutil.TempFile("", "")
			Expect(err).To(Succeed())

			_, err = manifestFile.Write(manifest)
			Expect(err).To(Succeed())
			manifestFile.Close()

			manifestPathRDP, err = filepath.Abs(manifestFile.Name())
			Expect(err).To(Succeed())
		}

		err := bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameRDP, manifestPathRDP))
		Expect(err).To(Succeed())

		// Regenerate the manifest
		{
			manifest, err := config.generateManifestRDP(deploymentNameRDP, false)
			Expect(err).To(Succeed())

			err = ioutil.WriteFile(manifestPathRDP, manifest, 0644)
			Expect(err).To(Succeed())
		}

		err = bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameRDP, manifestPathRDP))
		Expect(err).To(Succeed())
	})

	AfterSuite(func() {
		bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentName))
		bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNameSSH))
		bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNameRDP))

		Expect(bosh.Run("clean-up --all")).To(Succeed())
		if bosh.CertPath != "" {
			Expect(os.RemoveAll(bosh.CertPath)).To(Succeed())
		}
		if bosh.GwPrivateKeyPath != "" {
			Expect(os.RemoveAll(bosh.GwPrivateKeyPath)).To(Succeed())
		}
		if manifestPathSSH != "" {
			Expect(os.RemoveAll(manifestPathSSH)).To(Succeed())
		}
		if manifestPathRDP != "" {
			os.RemoveAll(manifestPathRDP)
		}
		if manifestPath != "" {
			Expect(os.RemoveAll(manifestPath)).To(Succeed())
		}
	})
})
