package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"cspm-dashboard/backend/api"
	"cspm-dashboard/backend/scanners"
)

func main() {
	ctx := context.Background()

	// Load AWS credentials using the default credential chain. The chain tries
	// each source in order and stops at the first one that works:
	//   1. Environment variables (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY)
	//   2. Shared credentials file (~/.aws/credentials)
	//   3. AWS SSO / IAM Identity Center
	//   4. EC2/ECS/Lambda instance metadata (when running inside AWS)
	//
	// The region is read from AWS_REGION (or AWS_DEFAULT_REGION), then from
	// ~/.aws/config, then falls back to "us-east-1". You can override it by
	// setting AWS_REGION in your environment before starting the server.
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(envOrDefault("AWS_REGION", envOrDefault("AWS_DEFAULT_REGION", "us-east-1"))),
	)
	if err != nil {
		log.Fatalf("failed to load AWS config: %v", err)
	}

	// Resolve the account ID from STS before initialising any scanner.
	// GetCallerIdentity is a lightweight call that requires no extra IAM
	// permissions — every authenticated identity can call it by design.
	// It also validates that credentials are working before the first scan.
	accountID, err := resolveAccountID(ctx, cfg)
	if err != nil {
		log.Fatalf("failed to resolve AWS account ID: %v\n"+
			"Ensure AWS credentials are configured (see 'aws configure' or set "+
			"AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY).", err)
	}

	log.Printf("account: %s | region: %s", accountID, cfg.Region)

	// Initialise all four scanners. Each holds its own AWS service client built
	// from cfg, so they all share the same credentials and region. Adding a new
	// scanner in the future is a one-line change here.
	allScanners := []scanners.Scanner{
		scanners.NewS3Scanner(cfg, accountID),
		scanners.NewIAMScanner(cfg, accountID),
		scanners.NewEC2Scanner(cfg, accountID),
		scanners.NewCloudTrailScanner(cfg, accountID),
	}

	// Build the HTTP server and register all routes + middleware.
	srv := api.NewServer(allScanners)

	addr := ":" + envOrDefault("PORT", "8080")
	log.Printf("listening on %s", addr)
	log.Printf("endpoints:")
	log.Printf("  GET %s/api/health           — liveness check", addr)
	log.Printf("  GET %s/api/scan             — full scan, returns all findings", addr)
	log.Printf("  GET %s/api/findings/summary — finding counts by severity and service", addr)

	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// resolveAccountID calls STS GetCallerIdentity and returns the 12-digit AWS
// account ID of the currently authenticated principal. This is the recommended
// way to discover the account ID programmatically — it is cheaper and more
// reliable than parsing it out of a resource ARN.
func resolveAccountID(ctx context.Context, cfg aws.Config) (string, error) {
	stsClient := sts.NewFromConfig(cfg)
	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("sts:GetCallerIdentity: %w", err)
	}
	return aws.ToString(out.Account), nil
}

// envOrDefault returns the value of the environment variable named key, or
// fallback if the variable is unset or empty.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
