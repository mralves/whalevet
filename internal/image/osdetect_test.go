package image

import "testing"

func TestDetectOSFromFROM(t *testing.T) {
	tests := []struct {
		from string
		want OSFamily
	}{
		{"FROM alpine:3.20", OSAlpine},
		{"FROM alpine:edge AS build", OSAlpine},
		{"FROM ubuntu:24.04", OSUbuntu},
		{"FROM debian:12", OSDebian},
		{"FROM centos:7", OSCentOS},
		{"FROM fedora:41", OSFedora},
		{"FROM rhel:9", OSRHEL},
		{"FROM rocky:9", OSRocky},
		{"FROM rockylinux:9", OSRocky},
		{"FROM rockylinux/rockylinux:9", OSRocky},
		{"FROM rockylinux:9 AS final", OSRocky},
		{"FROM almalinux:9", OSAlmaLinux},
		{"FROM amazonlinux:2023", OSAmazonLinux},
		{"FROM archlinux:latest", OSArch},
		{"FROM opensuse/leap:15.6", OSOpenSUSE},
		{"FROM --platform=linux/amd64 rockylinux:9", OSRocky},
		{"FROM rockylinux:9@sha256:abc", OSRocky},
		{"FROM busybox:latest", OSUnknown},
	}
	for _, tt := range tests {
		if got := DetectOSFromFROM(tt.from); got != tt.want {
			t.Errorf("DetectOSFromFROM(%q) = %v, want %v", tt.from, got, tt.want)
		}
	}
}
