// Package storage provides read access to the private QRIS document bucket.
//
// The portal never writes new objects (the gateway owns uploads); it only
// streams bytes back to a token-validated viewer and, via the retention sweep,
// deletes expired objects. No public URL is ever produced.
package storage

import (
	"bytes"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	appconfig "github.com/GTDGit/gtd_files_qris/internal/config"
)

// Storage is the minimal read/delete contract the portal needs.
type Storage interface {
	Get(ctx context.Context, key string) ([]byte, string, error)
	Delete(ctx context.Context, key string) error
}

// S3Storage reads from the private Jakarta bucket.
type S3Storage struct {
	client *s3.Client
	bucket string
}

// NewS3Storage builds an S3 client from StorageConfig.
func NewS3Storage(ctx context.Context, cfg appconfig.StorageConfig) (*S3Storage, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("storage: S3_BUCKET is required")
	}

	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(cfg.Region))
	if cfg.AccessKey != "" && cfg.SecretKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("storage: load aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = true
		}
	})

	return &S3Storage{client: client, bucket: cfg.Bucket}, nil
}

// Get downloads object bytes and content type.
func (s *S3Storage) Get(ctx context.Context, key string) ([]byte, string, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, "", fmt.Errorf("storage: get %s: %w", key, err)
	}
	defer out.Body.Close()

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(out.Body); err != nil {
		return nil, "", fmt.Errorf("storage: read %s: %w", key, err)
	}
	ct := ""
	if out.ContentType != nil {
		ct = *out.ContentType
	}
	return buf.Bytes(), ct, nil
}

// Delete removes the object at key (retention sweep).
func (s *S3Storage) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("storage: delete %s: %w", key, err)
	}
	return nil
}
