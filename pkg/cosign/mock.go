package cosign

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

func SetMock(image string, data [][]byte) error {
	imgRef, err := name.ParseReference(image)
	if err != nil {
		return err
	}

	payloads := make([]cosign.SignedPayload, len(data))
	for i, p := range data {
		payloads[i] = cosign.SignedPayload{
			Payload: p,
		}
	}

	client = &mock{data: map[string][]cosign.SignedPayload{
		imgRef.String(): payloads,
	}}

	return nil
}

func ClearMock() {
	client = &driver{}
}

type mock struct {
	data map[string][]cosign.SignedPayload
}

func (m *mock) VerifyImageSignatures(_ context.Context, signedImgRef name.Reference, _ *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	return m.getSignatures(signedImgRef)
}

func (m *mock) VerifyImageAttestations(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedAttestations []oci.Signature, bundleVerified bool, err error) {
	return m.getSignatures(signedImgRef)
}

func (m *mock) getSignatures(signedImgRef name.Reference) ([]oci.Signature, bool, error) {
	results, ok := m.data[signedImgRef.String()]
	if !ok {
		return nil, false, fmt.Errorf("failed to find mock data for %s", signedImgRef.String())
	}

	sigs := make([]oci.Signature, 0, len(results))
	for _, sp := range results {
		sigs = append(sigs, &sig{cosignPayload: sp})
	}

	return sigs, true, nil
}

type sig struct {
	sg            oci.Signature
	cosignPayload cosign.SignedPayload
}

func (s *sig) Payload() ([]byte, error) {
	return s.cosignPayload.Payload, nil
}

func (s *sig) Digest() (v1.Hash, error) {
	return s.sg.Digest()
}
func (s *sig) DiffID() (v1.Hash, error) {
	return s.sg.DiffID()
}
func (s *sig) Compressed() (io.ReadCloser, error) {
	return s.sg.Compressed()
}
func (s *sig) Uncompressed() (io.ReadCloser, error) {
	return s.sg.Uncompressed()
}
func (s *sig) Size() (int64, error) {
	return s.sg.Size()
}
func (s *sig) MediaType() (types.MediaType, error) {
	return s.sg.MediaType()
}
func (s *sig) Annotations() (map[string]string, error) {
	return s.sg.Annotations()
}
func (s *sig) Signature() ([]byte, error) {
	return s.sg.Signature()
}
func (s *sig) Base64Signature() (string, error) {
	return s.sg.Base64Signature()
}
func (s *sig) Cert() (*x509.Certificate, error) {
	return s.sg.Cert()
}
func (s *sig) Chain() ([]*x509.Certificate, error) {
	return s.sg.Chain()
}
func (s *sig) Bundle() (*bundle.RekorBundle, error) {
	return s.sg.Bundle()
}
func (s *sig) RFC3161Timestamp() (*bundle.RFC3161Timestamp, error) {
	return s.sg.RFC3161Timestamp()
}
