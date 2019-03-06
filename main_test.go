package wuts_test

import (
	"bytes"
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
	bosh              *BoshCommand
	stemcellInfo      ManifestInfo
	releaseVersion    string
	winUtilRelVersion string
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(GinkgoWriter)
}

var _ = Describe("Windows Utilities Release", func() {
	var config *Config

	SynchronizedBeforeSuite(func() []byte {
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

		matches, err := filepath.Glob(config.StemcellPath)
		Expect(err).To(Succeed())
		Expect(matches).To(HaveLen(1))

		stemcellInfo, err = fetchManifestInfo(matches[0], "stemcell.MF")
		Expect(err).To(Succeed())

		releaseVersion = createAndUploadRelease(filepath.Join("assets", "wuts-release"))
		winUtilRelVersion = createAndUploadRelease(config.WindowsUtilitiesPath)

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
			err = bosh.Run(fmt.Sprintf("upload-stemcell %s", matches[0]))
		}
		Expect(err).To(Succeed())
		return []byte(fmt.Sprintf("%s#%s", releaseVersion, winUtilRelVersion))
	}, func(versions []byte) {
		dividerIndex := bytes.Index(versions, []byte{'#'})
		releaseVersion = string(versions[:dividerIndex])
		winUtilRelVersion = string(versions[dividerIndex+1:])
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

		matches, err := filepath.Glob(config.StemcellPath)
		Expect(err).To(Succeed())
		Expect(matches).To(HaveLen(1))

		stemcellInfo, err = fetchManifestInfo(matches[0], "stemcell.MF")
		Expect(err).To(Succeed())

		bosh = NewBoshCommand(config, boshCertPath, boshGwPrivateKeyPath, timeout)
	})

	SynchronizedAfterSuite(func() {
	}, func() {
		if config.SkipCleanup {
			return
		}

		Expect(bosh.Run(fmt.Sprintf("delete-stemcell %s/%s", stemcellInfo.Name, stemcellInfo.Version))).To(Succeed())
		Expect(bosh.Run(fmt.Sprintf("delete-release wuts-release/%s", releaseVersion))).To(Succeed())
		Expect(bosh.Run(fmt.Sprintf("delete-release windows-utilities/%s", winUtilRelVersion))).To(Succeed())
	})

	Context("KMS", func() {
		var (
			deploymentNameKMS string
			manifestPathKMS   string
		)

		BeforeEach(func() {
			var err error

			deploymentNameKMS = fmt.Sprintf("windows-utilities-test-kms-%d", time.Now().UTC().UnixNano())
			manifestPathKMS, err = config.generateDefaultManifest(deploymentNameKMS)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			Expect(bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNameKMS))).To(Succeed())
			Expect(os.RemoveAll(manifestPathKMS)).To(Succeed())
		})

		It("enables KMS with Host and custom Port", func() {
			err := bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameKMS, manifestPathKMS))
			Expect(err).To(Succeed())
			err = bosh.Run(fmt.Sprintf("-d %s run-errand kms-host-enabled", deploymentNameKMS))
			Expect(err).To(Succeed())
		})

		It("does not enable KMS", func() {
			err := bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameKMS, manifestPathKMS))
			Expect(err).To(Succeed())
			err = bosh.Run(fmt.Sprintf("-d %s run-errand kms-host-not-enabled", deploymentNameKMS))
			Expect(err).To(Succeed())
		})

		It("enables KMS with Host and default Port", func() {
			err := bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameKMS, manifestPathKMS))
			Expect(err).To(Succeed())
			err = bosh.Run(fmt.Sprintf("-d %s run-errand kms-host-enabled-with-default", deploymentNameKMS))
			Expect(err).To(Succeed())
		})
	})

	Context("Set Password", func() {
		var (
			deploymentNamePassword string
			manifestPathPassword   string
		)

		BeforeEach(func() {
			var err error

			deploymentNamePassword = fmt.Sprintf("windows-utilities-test-password-%d", time.Now().UTC().UnixNano())
			manifestPathPassword, err = config.generateDefaultManifest(deploymentNamePassword)
			Expect(err).To(Succeed())
		})

		AfterEach(func() {
			Expect(bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNamePassword))).To(Succeed())
			Expect(os.RemoveAll(manifestPathPassword)).To(Succeed())
		})

		It("sets Administrator password correctly", func() {
			err := bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNamePassword, manifestPathPassword))
			Expect(err).To(Succeed())
			err = bosh.Run(fmt.Sprintf("-d %s run-errand set-admin-password", deploymentNamePassword))
			Expect(err).To(Succeed())
		})
	})

	Context("SSH", func() {
		var (
			deploymentNameSSH string
			manifestPathSSH   string
			manifestPathNoSSH string
		)

		BeforeEach(func() {
			var err error

			deploymentNameSSH = fmt.Sprintf("windows-utilities-test-ssh-%d", time.Now().UTC().UnixNano())

			manifestPathSSH, err = config.generateManifestSSH(deploymentNameSSH, true)
			Expect(err).NotTo(HaveOccurred())

			manifestPathNoSSH, err = config.generateManifestSSH(deploymentNameSSH, false)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			Expect(bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNameSSH))).To(Succeed())
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

	Context("RDP", func() {
		var (
			deploymentNameRDP string
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

			deploymentNameRDP = fmt.Sprintf("windows-utilities-test-rdp-%d", time.Now().UTC().UnixNano())

			manifestPathRDP, err = config.generateManifestRDP(deploymentNameRDP, instanceName, true, username, password)
			Expect(err).NotTo(HaveOccurred())

			manifestPathNoRDP, err = config.generateManifestRDP(deploymentNameRDP, instanceName, false, username, password)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if config.SkipCleanupOnRDPFail && CurrentGinkgoTestDescription().Failed {
				return
			}
			Expect(bosh.Run(fmt.Sprintf("-d %s delete-deployment --force", deploymentNameRDP))).To(Succeed())
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
				rdpSession, err := runCommand("/bin/bash", "-c", "/usr/local/bin/rdp-sec-check.pl localhost")
				Eventually(rdpSession, 30*time.Second).Should(Exit())

				return rdpSession, err
			}, 3*time.Minute).Should(Exit(0))

			Expect(bosh.Run(fmt.Sprintf("-d %s deploy %s", deploymentNameRDP, manifestPathNoRDP))).To(Succeed())

			disabledSession := config.doSSHLogin(instanceIP)
			Eventually(disabledSession, 60*time.Second).Should(Exit())
			Eventually(disabledSession.Err).Should(Say(`Could not request local forwarding.`))
		})
	})
})
