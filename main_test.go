package wuts_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
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
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
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
	RDPEnabled         bool
	SetPasswordEnabled bool
	InstanceName       string
	Username           string
	Password           string
}

func (c *Config) generateManifestRDP(deploymentName string, instanceName string, enabled bool, username string, password string) (string, error) {
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
		RDPEnabled:         enabled,
		SetPasswordEnabled: enabled,
		InstanceName:       instanceName,
		Username:           username,
		Password:           password,
	}

	templ, err := template.New("").Parse(RdpTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = templ.Execute(&buf, manifestProperties)
	if err != nil {
		return "", err
	}

	manifest := buf.Bytes()
	log.Print("\nRDP Manifest: " + string(manifest[:]) + "\n")

	manifestDir, err := ioutil.TempDir("", "")

	if err != nil {
		return "", err
	}

	manifestPathRDP := filepath.Join(manifestDir, "rdp.yml")
	err = ioutil.WriteFile(manifestPathRDP, manifest, 0644)
	if err != nil {
		return "", err
	}

	return manifestPathRDP, nil
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

	session, err := Start(cmd, GinkgoWriter, GinkgoWriter)
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

	session, err := Start(cmd, GinkgoWriter, GinkgoWriter)
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

func doSSHLogin(targetIP string) *Session {
	sshLoginDone := make(chan bool, 1)
	var session *Session

	go func() {
		defer GinkgoRecover()

		directorAddress := strings.Split(bosh.DirectorIP, ":")[0]

		var err error
		session, err = runCommand("ssh", "-nNT", fmt.Sprintf("%s@%s", bosh.GwUser, directorAddress), "-i", bosh.GwPrivateKeyPath, "-L", fmt.Sprintf("3389:%s:3389", targetIP), "-o", "StrictHostKeyChecking=no", "-o", "ExitOnForwardFailure=yes")
		Expect(err).NotTo(HaveOccurred())
		time.Sleep(5 * time.Second)

		sshLoginDone <- true
	}()

	<-sshLoginDone

	return session
}

func runCommand(cmd string, args ...string) (*Session, error) {
	return Start(exec.Command(cmd, args...), GinkgoWriter, GinkgoWriter)
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
func downloadLogs(jobName string, index int) *Buffer {
	tempDir, err := ioutil.TempDir("", "")
	Expect(err).To(Succeed())
	defer os.RemoveAll(tempDir)

	err = bosh.Run(fmt.Sprintf("-d %s logs %s/%d --dir %s", deploymentName, jobName, index, tempDir))
	Expect(err).To(Succeed())

	matches, err := filepath.Glob(filepath.Join(tempDir, fmt.Sprintf("%s.%s.%d-*.tgz", deploymentName, jobName, index)))
	Expect(err).To(Succeed())
	Expect(matches).To(HaveLen(1))

	cmd := exec.Command("tar", "xf", matches[0], "-O", fmt.Sprintf("./%s/%s/job-service-wrapper.out.log", jobName, jobName))
	session, err := Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).To(Succeed())

	return session.Wait().Out
}

type vmInfo struct {
	Tables []struct {
		Rows []struct {
			Instance string `json:"instance"`
			IPs      string `json:"ips"`
		} `json:"Rows"`
	} `json:"Tables"`
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
	session, err := Start(cmd, GinkgoWriter, GinkgoWriter)
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

func generateSemiRandomWindowsPassword() string {
	var (
		validChars []rune
		password   string
	)

	for i := '!'; i <= '~'; i++ {
		if i != '\'' && i != '"' && i != '`' && i != '\\' {
			validChars = append(validChars, i)
		}
	}

	for i := 0; i < 10; i++ {
		randomIndex := rand.Intn(len(validChars))
		password = password + string(validChars[randomIndex])
	}

	// ensure compliance with Windows password requirements
	password = password + "Ab!"
	return password
}

func getFirstInstanceIP(deployment string, instanceName string) (string, error) {
	var vms vmInfo
	stdout, err := bosh.RunInStdOut(fmt.Sprintf("vms -d %s --json", deployment), "")
	if err != nil {
		return "", err
	}

	if err = json.Unmarshal(stdout, &vms); err != nil {
		return "", err
	}

	for _, row := range vms.Tables[0].Rows {
		if strings.HasPrefix(row.Instance, instanceName) {
			ips := strings.Split(row.IPs, "\n")
			if len(ips) == 0 {
				break
			}
			return ips[0], nil
		}
	}

	return "", errors.New("No instance IPs found!")
}

var _ = Describe("Windows Utilities Release", func() {
	var config *Config

	BeforeSuite(func() {
		var err error
		config, err = NewConfig()
		Expect(err).To(Succeed())

		rand.Seed(time.Now().UnixNano())

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
		Expect(json.Unmarshal(stdout, &stdoutInfo)).To(Succeed())
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

	AfterSuite(func() {
		if config.SkipCleanup {
			return
		}

		Expect(bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentName))).To(Succeed())
		Expect(bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNameSSH))).To(Succeed())
		Expect(bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNameRDP))).To(Succeed())
		Expect(bosh.Run(fmt.Sprintf("delete-stemcell %s/%s", stemcellName, stemcellVersion))).To(Succeed())
		Expect(bosh.Run(fmt.Sprintf("delete-release wuts-release/%s", releaseVersion))).To(Succeed())
		Expect(bosh.Run(fmt.Sprintf("delete-release windows-utilities/%s", winUtilRelVersion))).To(Succeed())

		if manifestPathSSH != "" {
			Expect(os.RemoveAll(manifestPathSSH)).To(Succeed())
		}
		if manifestPath != "" {
			Expect(os.RemoveAll(manifestPath)).To(Succeed())
		}
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

	Context("RDP", func() {
		var (
			username          string
			password          string
			instanceName      string
			manifestPathRDP   string
			manifestPathNoRDP string
		)

		BeforeEach(func() {
			var err error

			instanceName = "check-rdp"
			username = "Administrator"
			password = generateSemiRandomWindowsPassword()

			manifestPathRDP, err = config.generateManifestRDP(deploymentNameRDP, instanceName, true, username, password)
			Expect(err).NotTo(HaveOccurred())

			manifestPathNoRDP, err = config.generateManifestRDP(deploymentNameRDP, instanceName, true, username, password)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			Expect(os.RemoveAll(manifestPathRDP)).To(Succeed())
			Expect(os.RemoveAll(manifestPathNoRDP)).To(Succeed())
		})

		It("Enables and then disables RDP", func() {
			Expect(bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameRDP, manifestPathRDP))).To(Succeed())

			instanceIP, err := getFirstInstanceIP(deploymentNameRDP, instanceName)
			Expect(err).NotTo(HaveOccurred())

			enabledSession := doSSHLogin(instanceIP)
			defer enabledSession.Kill()

			Eventually(func() (*Session, error) {
				rdpSession, err := runCommand("/bin/bash", "-c", fmt.Sprintf("xfreerdp /cert-ignore /u:%s /p:'%s' /v:localhost:3389 +auth-only", username, password))
				Eventually(rdpSession, 30*time.Second).Should(Exit())

				return rdpSession, err
			}, 3*time.Minute).Should(Exit(0))

			Expect(bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameRDP, manifestPathNoRDP))).To(Succeed())

			disabledSession := doSSHLogin(instanceIP)
			Eventually(disabledSession).Should(Exit())
			Eventually(disabledSession.Err).Should(Say(`Could not request local forwarding.`))
		})
	})

})
