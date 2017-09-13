package main

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestWindowsUtilitiesTests(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "WindowsUtilitiesTests Suite")
}
