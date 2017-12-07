package wuts_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	. "github.com/cloudfoundry-incubator/windows-utilities-tests/templates"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"gopkg.in/yaml.v2"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(GinkgoWriter)
}

const BOSH_TIMEOUT = 90 * time.Minute
const GoZipFile = "go1.7.1.windows-amd64.zip"
const GolangURL = "https://storage.googleapis.com/golang/" + GoZipFile

type ManifestProperties struct {
	DeploymentName  string
	ReleaseName     string
	AZ              string
	VmType          string
	VmExtensions    string
	Network         string
	StemcellOS      string
	StemcellVersion string
	WinUtilVersion  string
	WutsVersion     string
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
	SkipCleanup          bool   `json:"skip_cleanup"`
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
		DeploymentName:  deploymentName,
		ReleaseName:     "wuts-release",
		AZ:              c.Az,
		VmType:          c.VmType,
		VmExtensions:    c.VmExtensions,
		Network:         c.Network,
		StemcellOS:      c.StemcellOS,
		StemcellVersion: stemcellVersion,
		WinUtilVersion:  winUtilRelVersion,
		WutsVersion:     releaseVersion,
	}
	templ, err := template.New("").Parse(ManifestTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = templ.Execute(&buf, manifestProperties)

	manifest := buf.Bytes()
	log.Print("\nDeployment Manifest: " + string(manifest[:]) + "\n")

	return manifest, err
}

type SSHManifestProperties struct {
	ManifestProperties
	SSHEnabled bool
}

func (c *Config) generateManifestSSH(deploymentName string, enabled bool) ([]byte, error) {
	manifestProperties := SSHManifestProperties{
		ManifestProperties: ManifestProperties{
			DeploymentName:  deploymentName,
			ReleaseName:     "wuts-release",
			AZ:              c.Az,
			VmType:          c.VmType,
			VmExtensions:    c.VmExtensions,
			Network:         c.Network,
			StemcellOS:      c.StemcellOS,
			StemcellVersion: stemcellVersion,
			WinUtilVersion:  winUtilRelVersion,
			WutsVersion:     releaseVersion,
		},
		SSHEnabled: enabled,
	}
	templ, err := template.New("").Parse(SshTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = templ.Execute(&buf, manifestProperties)

	manifest := buf.Bytes()
	log.Print("\nSSH Manifest: " + string(manifest[:]) + "\n")

	return manifest, err
}

type RDPManifestProperties struct {
	ManifestProperties
	RDPEnabled bool
}

func (c *Config) generateManifestRDP(deploymentName string, enabled bool) ([]byte, error) {
	manifestProperties := RDPManifestProperties{
		ManifestProperties: ManifestProperties{
			DeploymentName:  deploymentName,
			ReleaseName:     "wuts-release",
			AZ:              c.Az,
			VmType:          c.VmType,
			VmExtensions:    c.VmExtensions,
			Network:         c.Network,
			StemcellOS:      c.StemcellOS,
			StemcellVersion: stemcellVersion,
			WinUtilVersion:  winUtilRelVersion,
			WutsVersion:     releaseVersion,
		},
		RDPEnabled: enabled,
	}
	templ, err := template.New("").Parse(RdpTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = templ.Execute(&buf, manifestProperties)

	manifest := buf.Bytes()
	log.Print("\nRDP Manifest: " + string(manifest[:]) + "\n")

	return manifest, err
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

func (c *BoshCommand) RunInStdOut(command, dir string) ([]byte, error) {
	cmd := exec.Command("bosh", c.args(command)...)
	if dir != "" {
		cmd.Dir = dir
		log.Printf("\nRUNNING %q IN %q\n", strings.Join(cmd.Args, " "), dir)
	} else {
		log.Printf("\nRUNNING %q\n", strings.Join(cmd.Args, " "))
	}

	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	if err != nil {
		return nil, err
	}
	session.Wait(c.Timeout)

	exitCode := session.ExitCode()
	stdout := session.Out.Contents()
	if exitCode != 0 {
		var stderr []byte
		if session.Err != nil {
			stderr = session.Err.Contents()
		}
		return stdout, fmt.Errorf("Non-zero exit code for cmd %q: %d\nSTDERR:\n%s\nSTDOUT:%s\n",
			strings.Join(cmd.Args, " "), exitCode, stderr, stdout)
	}
	return stdout, nil
}

//noinspection GoUnusedFunction
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

//noinspection GoUnusedFunction
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

type BoshStemcell struct {
	Tables []struct {
		Rows []struct {
			Version string `json:"version"`
		} `json:"Rows"`
	} `json:"Tables"`
}

type ManifestInfo struct {
	Version string `yaml:"version"`
	Name    string `yaml:"name"`
}

func fetchManifestInfo(releasePath string, manifestFilename string) (ManifestInfo, error) {
	var stemcellInfo ManifestInfo
	tempDir, err := ioutil.TempDir("", "")
	Expect(err).To(Succeed())
	defer os.RemoveAll(tempDir)

	cmd := exec.Command("tar", "xf", releasePath, "-C", tempDir, manifestFilename)
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).To(Succeed())
	session.Wait(20 * time.Minute)

	exitCode := session.ExitCode()
	if exitCode != 0 {
		var stderr []byte
		if session.Err != nil {
			stderr = session.Err.Contents()
		}
		stdout := session.Out.Contents()
		return stemcellInfo, fmt.Errorf("Non-zero exit code for cmd %q: %d\nSTDERR:\n%s\nSTDOUT:%s\n",
			strings.Join(cmd.Args, " "), exitCode, stderr, stdout)
	}

	stemcellMF, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", tempDir, manifestFilename))
	Expect(err).To(Succeed())

	err = yaml.Unmarshal(stemcellMF, &stemcellInfo)
	Expect(err).To(Succeed())
	Expect(stemcellInfo.Version).ToNot(BeNil())
	Expect(stemcellInfo.Version).ToNot(BeEmpty())

	return stemcellInfo, nil
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
	stemcellName      string
	stemcellVersion   string
	releaseVersion    string
	winUtilRelVersion string
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

func createAndUploadRelease(releaseDir string) string {
	pwd, err := os.Getwd()
	Expect(err).To(Succeed())

	absoluteFilePath := filepath.Join(pwd, releaseDir)
	Expect(os.Chdir(absoluteFilePath)).To(Succeed())
	defer os.Chdir(pwd)

	version := fmt.Sprintf("0.dev+%d", getTimestampInMs())

	Expect(bosh.Run(fmt.Sprintf("create-release --force --version %s", version))).To(Succeed())
	Expect(bosh.Run("upload-release")).To(Succeed())

	return version
}

func getTimestampInMs() int64 {
	return time.Now().UTC().UnixNano() / int64(time.Millisecond)
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

		matches, err := filepath.Glob(config.StemcellPath)
		Expect(err).To(Succeed())
		Expect(matches).To(HaveLen(1))

		var stemcellInfo ManifestInfo
		stemcellInfo, err = fetchManifestInfo(matches[0], "stemcell.MF")
		Expect(err).To(Succeed())

		stemcellVersion = stemcellInfo.Version
		stemcellName = stemcellInfo.Name

		// get the output of bosh stemcells
		var stdout []byte
		stdout, err = bosh.RunInStdOut("stemcells --json", "")
		Expect(err).To(Succeed())

		// Ensure stemcell version has not already been uploaded to bosh director
		var stdoutInfo BoshStemcell
		json.Unmarshal(stdout, &stdoutInfo)
		for _, row := range stdoutInfo.Tables[0].Rows {
			Expect(row.Version).NotTo(ContainSubstring(stemcellVersion))
		}

		releaseVersion = createAndUploadRelease(filepath.Join("assets", "wuts-release"))
		winUtilRelVersion = createAndUploadRelease(config.WindowsUtilitiesPath)

		// Generate main manifest
		manifest, err := config.generateManifest(deploymentName)
		Expect(err).To(Succeed())
		manifestFile, err := ioutil.TempFile("", "")
		Expect(err).To(Succeed())
		_, err = manifestFile.Write(manifest)
		Expect(err).To(Succeed())
		manifestPath, err = filepath.Abs(manifestFile.Name())
		Expect(err).To(Succeed())

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

	It("Sets Administrator password correctly", func() {
		err := bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentName, manifestPath))
		Expect(err).To(Succeed())
		err = bosh.Run(fmt.Sprintf("-d %s run-errand set-admin-password", deploymentName))
		Expect(err).To(Succeed())
	})

	It("Enables and then disables SSH", func() {
		directorURL, err := url.Parse(fmt.Sprintf("http://%s", bosh.DirectorIP))

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
		if config.SkipCleanup {
			return
		}

		bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentName))
		bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNameSSH))
		bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNameRDP))
		bosh.Run(fmt.Sprintf("delete-stemcell %s/%s", stemcellName, stemcellVersion))
		bosh.Run(fmt.Sprintf("delete-release wuts-release/%s", releaseVersion))
		bosh.Run(fmt.Sprintf("delete-release windows-utilities/%s", winUtilRelVersion))

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
