package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/armon/go-socks5"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"golang.org/x/crypto/ssh"
)

const (
	region       = "eu-north-1"
	amiID        = "ami-0b46816ffa1234887"
	instanceType = types.InstanceTypeT3Micro
	keyPairName  = ""
	sshUser      = "ec2-user"
	privateKey   = ""
	socksAddr    = ""
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))

	if err != nil {
		slog.Error("Failed to load AWS config", "err", err)
		os.Exit(1)
	}

	ec2Client := ec2.NewFromConfig(cfg)

	slog.Info("Launching EC2 instance...")

	instanceId, ipAddr, err := launchInstance(ctx, ec2Client)

	if err != nil {
		slog.Error("Failed to launch instance", "err", err)
		os.Exit(1)
	}

	defer terminateInstance(context.Background(), ec2Client, instanceId)

	slog.Info("EC2 instance ready", "instanceId", instanceId, "ipAddr", ipAddr)

	sshClient, err := connectSSH(ipAddr)

	if err != nil {
		slog.Error("Failed to create SSS tunnel", "err", err)
		terminateInstance(context.Background(), ec2Client, instanceId)
		os.Exit(1)
	}

	defer sshClient.Close()

	startSocksProxy(ctx, sshClient)

	waitForSignal()

	slog.Info("Shutting down...")
}

func launchInstance(ctx context.Context, ec2Client *ec2.Client) (string, string, error) {
	runOut, err := ec2Client.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId:      aws.String(amiID),
		InstanceType: instanceType,
		KeyName:      aws.String(keyPairName),
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
	})

	if err != nil {
		return "", "", fmt.Errorf("RunInstances failed: %w", err)
	}

	instanceID := *runOut.Instances[0].InstanceId

	waiter := ec2.NewInstanceRunningWaiter(ec2Client)

	err = waiter.Wait(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}, 5*time.Minute)

	if err != nil {
		return "", "", fmt.Errorf("Instance waiter failed: %w", err)
	}

	desc, err := ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})

	if err != nil {
		return "", "", fmt.Errorf("Failed to get instance info: %w", err)
	}

	ip := *desc.Reservations[0].Instances[0].PublicIpAddress

	return instanceID, ip, nil
}

func terminateInstance(ctx context.Context, ec2Client *ec2.Client, instanceID string) {
	fmt.Println("Terminating instance:", instanceID)
	_, err := ec2Client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		slog.Error("Error while terminating instance", "err", err)
	}
}

func connectSSH(ip string) (*ssh.Client, error) {
	key, err := os.ReadFile(privateKey)

	if err != nil {
		return nil, fmt.Errorf("Unable to read SSH key file: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(key)

	if err != nil {
		return nil, fmt.Errorf("Unable to parse SSH key file: %w", err)
	}

	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:22", ip)

	slog.Info("Creating SSH tunnel", "addr", addr)

	client, err := ssh.Dial("tcp", addr, config)

	if err != nil {
		return nil, fmt.Errorf("Unable to connect to SSH server: %w", err)
	}

	return client, nil
}

func startSocksProxy(ctx context.Context, sshClient *ssh.Client) error {
	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sshClient.Dial(network, addr)
		},
	}

	server, err := socks5.New(conf)

	if err != nil {
		return fmt.Errorf("Error creating SOCKS server: %w", err)
	}

	ln, err := net.Listen("tcp", socksAddr)

	if err != nil {
		return fmt.Errorf("Error establishing socket for SOCKS server: %w", err)
	}

	slog.Info("SOCKS server running", "addr", socksAddr)

	go func() {
		if err := server.Serve(ln); err != nil {
			slog.Info("SOCKS server exited", err)
		}
	}()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	return nil
}

func waitForSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
