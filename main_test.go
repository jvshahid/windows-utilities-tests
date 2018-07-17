package wuts_test

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var (
	bosh                  *BoshCommand
	defaultDeploymentName string
	deploymentNameSSH     string
	deploymentNameRDP     string
	defaultManifestPath   string
	boshCertPath          string
	stemcellInfo          ManifestInfo
	releaseVersion        string
	winUtilRelVersion     string
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(GinkgoWriter)
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

		timeout := BOSH_TIMEOUT
		if s := os.Getenv("WUTS_BOSH_TIMEOUT"); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil {
				log.Printf("Error parsing WUTS_BOSH_TIMEOUT (%s): %s - falling back to default\n", s, err)
			} else {
				log.Printf("Using WUTS_BOSH_TIMEOUT (%s) as timeout\n", s)
				timeout = d
			}
		}
		log.Printf("Using timeout (%s) for BOSH commands\n", timeout)

		bosh = NewBoshCommand(config, boshCertPath, boshGwPrivateKeyPath, timeout)

		Expect(bosh.Run("login")).To(Succeed())
		defaultDeploymentName = fmt.Sprintf("windows-utilities-test-%d", time.Now().UTC().Unix())
		deploymentNameSSH = fmt.Sprintf("windows-utilities-test-ssh-%d", time.Now().UTC().Unix())
		deploymentNameRDP = fmt.Sprintf("windows-utilities-test-rdp-%d", time.Now().UTC().Unix())

		matches, err := filepath.Glob(config.StemcellPath)
		Expect(err).To(Succeed())
		Expect(matches).To(HaveLen(1))

		stemcellInfo, err = fetchManifestInfo(matches[0], "stemcell.MF")
		Expect(err).To(Succeed())

		// get the output of bosh stemcells
		var stdout []byte
		stdout, err = bosh.RunInStdOut("stemcells --json", "")
		Expect(err).To(Succeed())

		// Ensure stemcell version has not already been uploaded to bosh director
		var stdoutInfo BoshStemcell
		Expect(json.Unmarshal(stdout, &stdoutInfo)).To(Succeed())
		// for _, row := range stdoutInfo.Tables[0].Rows {
		// 	Expect(row.Version).NotTo(MatchRegexp(fmt.Sprintf(`^%s\*?$`, stemcellInfo.Version)))
		// }

		releaseVersion = createAndUploadRelease(filepath.Join("assets", "wuts-release"))
		winUtilRelVersion = createAndUploadRelease(config.WindowsUtilitiesPath)

		// Generate default manifest
		defaultManifestPath, err = config.generateDefaultManifest(defaultDeploymentName)
		Expect(err).To(Succeed())

		// Upload latest stemcell
		matches, err = filepath.Glob(config.StemcellPath)
		Expect(err).To(Succeed(),
			fmt.Sprintf("expected to find stemcell at: %s", config.StemcellPath))
		Expect(matches).To(HaveLen(1),
			fmt.Sprintf("expected to find stemcell at: %s", config.StemcellPath))

		err = bosh.Run(fmt.Sprintf("upload-stemcell %s", matches[0]))
		if err != nil {
			// AWS takes a while to distribute the AMI across accounts
			time.Sleep(2 * time.Minute)
		}
		Expect(err).To(Succeed())
	})

	// AfterSuite(func() {
	// 	if config.SkipCleanup {
	// 		return
	// 	}

	// 	Expect(bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", defaultDeploymentName))).To(Succeed())
	// 	Expect(bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNameSSH))).To(Succeed())
	// 	Expect(bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNameRDP))).To(Succeed())
	// 	Expect(bosh.Run(fmt.Sprintf("delete-stemcell %s/%s", stemcellInfo.Name, stemcellInfo.Version))).To(Succeed())
	// 	Expect(bosh.Run(fmt.Sprintf("delete-release wuts-release/%s", releaseVersion))).To(Succeed())
	// 	Expect(bosh.Run(fmt.Sprintf("delete-release windows-utilities/%s", winUtilRelVersion))).To(Succeed())

	// 	if defaultManifestPath != "" {
	// 		Expect(os.RemoveAll(defaultManifestPath)).To(Succeed())
	// 	}
	// })

	Context("KMS", func() {
		It("enables KMS with Host and custom Port", func() {
			err := bosh.Run(fmt.Sprintf("-d %s deploy %s", defaultDeploymentName, defaultManifestPath))
			Expect(err).To(Succeed())
			err = bosh.Run(fmt.Sprintf("-d %s run-errand kms-host-enabled", defaultDeploymentName))
			Expect(err).To(Succeed())
		})

		It("does not enable KMS", func() {
			err := bosh.Run(fmt.Sprintf("-d %s deploy %s", defaultDeploymentName, defaultManifestPath))
			Expect(err).To(Succeed())
			err = bosh.Run(fmt.Sprintf("-d %s run-errand kms-host-not-enabled", defaultDeploymentName))
			Expect(err).To(Succeed())
		})

		It("enables KMS with Host and default Port", func() {
			err := bosh.Run(fmt.Sprintf("-d %s deploy %s", defaultDeploymentName, defaultManifestPath))
			Expect(err).To(Succeed())
			err = bosh.Run(fmt.Sprintf("-d %s run-errand kms-host-enabled-with-default", defaultDeploymentName))
			Expect(err).To(Succeed())
		})
	})

	Context("Set Password", func() {
		It("sets Administrator password correctly", func() {
			err := bosh.Run(fmt.Sprintf("-d %s deploy %s", defaultDeploymentName, defaultManifestPath))
			Expect(err).To(Succeed())
			err = bosh.Run(fmt.Sprintf("-d %s run-errand set-admin-password", defaultDeploymentName))
			Expect(err).To(Succeed())
		})
	})

	Context("SSH", func() {
		var (
			manifestPathSSH   string
			manifestPathNoSSH string
		)

		BeforeEach(func() {
			var err error

			manifestPathSSH, err = config.generateManifestSSH(deploymentNameSSH, true)
			Expect(err).NotTo(HaveOccurred())

			manifestPathNoSSH, err = config.generateManifestSSH(deploymentNameSSH, false)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			Expect(os.RemoveAll(manifestPathSSH)).To(Succeed())
			Expect(os.RemoveAll(manifestPathNoSSH)).To(Succeed())
		})

		It("enables and then disables SSH", func() {
			directorURL, err := url.Parse(fmt.Sprintf("http://%s", bosh.DirectorIP))

			Expect(err).NotTo(HaveOccurred())

			err = bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameSSH, manifestPathSSH))
			Expect(err).To(Succeed())

			// Try to ssh into windows cell
			err = bosh.Run(fmt.Sprintf("-d %s ssh --opts=-T --command=exit check-ssh/0 --gw-user %s --gw-host %s --gw-private-key %s", deploymentNameSSH, bosh.GwUser, directorURL.Hostname(), bosh.GwPrivateKeyPath))
			Expect(err).To(Succeed())

			err = bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameSSH, manifestPathNoSSH))
			Expect(err).To(Succeed())

			// Try to ssh into windows cell
			err = bosh.Run(fmt.Sprintf("-d %s ssh --opts=-T --command=exit check-ssh/0 --gw-user %s --gw-host %s --gw-private-key %s", deploymentNameSSH, bosh.GwUser, directorURL.Hostname(), bosh.GwPrivateKeyPath))
			Expect(err).NotTo(Succeed())
		})
	})

	FContext("RDP", func() {
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

			manifestPathNoRDP, err = config.generateManifestRDP(deploymentNameRDP, instanceName, false, username, password)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			Expect(os.RemoveAll(manifestPathRDP)).To(Succeed())
			Expect(os.RemoveAll(manifestPathNoRDP)).To(Succeed())
		})

		It("enables and then disables RDP", func() {
			Expect(bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameRDP, manifestPathRDP))).To(Succeed())

			instanceIP, err := getFirstInstanceIP(deploymentNameRDP, instanceName)
			Expect(err).NotTo(HaveOccurred())

			enabledSession := config.doSSHLogin(instanceIP)
			defer enabledSession.Kill()

			Eventually(func() (*Session, error) {
				rdpSession, err := runCommand("/bin/bash", "-c", fmt.Sprintf("xfreerdp /cert-ignore /u:%s /p:'%s' /v:localhost:3389 +auth-only", username, password))
				Eventually(rdpSession, 30*time.Second).Should(Exit())

				return rdpSession, err
			}, 3*time.Minute).Should(Exit(0))

			Expect(bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameRDP, manifestPathNoRDP))).To(Succeed())

			disabledSession := config.doSSHLogin(instanceIP)
			Eventually(disabledSession).Should(Exit())
			Eventually(disabledSession.Err).Should(Say(`Could not request local forwarding.`))
		})
	})
})
