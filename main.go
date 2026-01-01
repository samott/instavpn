package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	vpcID        = ""
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

	myIp, err := getMyIp()

	if err != nil {
		slog.Error("Failed to look up my IP address", "err", err)
		os.Exit(1)
	}

	slog.Info("Using my IP for firewall rule", "ip", myIp)

	securityGroupId, err := createSecurityGroup(ctx, ec2Client, myIp+"/32")

	if err != nil {
		slog.Error("Failed to create security group", "err", err)
		os.Exit(1)
	}

	slog.Info("Created security group", "id", securityGroupId)

	instanceId, ipAddr, err := launchInstance(ctx, ec2Client, securityGroupId)

	if err != nil {
		slog.Error("Failed to launch instance", "err", err)
		os.Exit(1)
	}

	defer deleteSecurityGroup(ctx, ec2Client, instanceId, securityGroupId)
	defer terminateInstance(context.Background(), ec2Client, instanceId)

	slog.Info("EC2 instance ready", "instanceId", instanceId, "ipAddr", ipAddr)

	sshClient, err := connectSSH(ipAddr)

	if err != nil {
		slog.Error("Failed to create SSH tunnel", "err", err)
		terminateInstance(context.Background(), ec2Client, instanceId)
		os.Exit(1)
	}

	defer sshClient.Close()

	startSocksProxy(ctx, sshClient)

	waitForSignal()

	slog.Info("Shutting down...")
}

func getMyIp() (string, error) {
	resp, err := http.Get("https://checkip.amazonaws.com/")

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	ip := strings.Trim(string(body), "\n")

	return ip, nil
}

func launchInstance(ctx context.Context, ec2Client *ec2.Client, securityGroupId string) (string, string, error) {
	slog.Info("Launching EC2 instance...")

	runOut, err := ec2Client.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId:      aws.String(amiID),
		InstanceType: instanceType,
		KeyName:      aws.String(keyPairName),
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
		SecurityGroupIds: []string{
			securityGroupId,
		},
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
	slog.Info("Terminating instance:", "id", instanceID)
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
			slog.Error("SOCKS server exited", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	return nil
}

func createSecurityGroup(
	ctx context.Context,
	ec2Client *ec2.Client,
	sshCIDR string,
) (string, error) {
	slog.Info("Creating security group...")

	// 1. Create the security group
	sgOut, err := ec2Client.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String("instavpn"),
		Description: aws.String("InstaVPN - Ephemeral SSH access"),
		VpcId:       aws.String(vpcID),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeSecurityGroup,
				Tags: []types.Tag{
					{Key: aws.String("Name"), Value: aws.String("instavpn")},
					{Key: aws.String("CreatedBy"), Value: aws.String("instavpn")},
					{Key: aws.String("Purpose"), Value: aws.String("SSH access")},
					{Key: aws.String("TTL"), Value: aws.String("1h")},
				},
			},
		},
	})
	if err != nil {
		return "", err
	}

	sgId := *sgOut.GroupId

	// 2. Allow inbound SSH
	_, err = ec2Client.AuthorizeSecurityGroupIngress(ctx,
		&ec2.AuthorizeSecurityGroupIngressInput{
			GroupId: aws.String(sgId),
			IpPermissions: []types.IpPermission{
				{
					IpProtocol: aws.String("tcp"),
					FromPort:   aws.Int32(22),
					ToPort:     aws.Int32(22),
					IpRanges: []types.IpRange{
						{CidrIp: aws.String(sshCIDR)},
					},
				},
			},
		})
	if err != nil {
		return "", err
	}

	return sgId, nil
}

func deleteSecurityGroup(ctx context.Context, ec2Client *ec2.Client, instanceId, sgId string) {
	slog.Info("Awaiting instance termination...")

	waiter := ec2.NewInstanceTerminatedWaiter(ec2Client)
	err := waiter.Wait(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceId},
	}, 5*time.Minute)

	if err != nil {
		slog.Error("Error waiting for instance termination", "err", err)
	}

	slog.Info("Deleting security group...")

	_, err = ec2Client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(sgId),
	})

	if err != nil {
		slog.Error("Error deleting security group", "err", err)
	}
}

func waitForSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
