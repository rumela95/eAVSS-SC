// Package evss implements eVSS found in section 4.1,
// A. Kate, et al.
// Constant-Size Commitments to Polynomials and Their Applications.

package evss

import (
	"crypto/rand"
	"io"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/zhtluo/libpolycrypto/polycommit"
	pb "github.com/zhtluo/libpolycrypto/proto"
	"google.golang.org/protobuf/proto"
)

var (
	MaxInt = bn256.Order
)

// Struct PublicInfo implements the public information available at the start of the phase.
type PublicInfo struct {
	Pk     polycommit.Pk
	Commit bn256.G2
}

// Struct Secret implements the secret the dealer wishes to share.
type Secret struct {
	Poly []big.Int
}

// Struct Secret implements the share of each node.
type Share struct {
	Index   big.Int
	Result  big.Int
	Witness bn256.G1
}

// Generate a secret with the constant term specified.
func GenerateSecret(r io.Reader, constant *big.Int, degree int) (*Secret, error) {
	s := new(Secret)
	s.Poly = make([]big.Int, degree)
	s.Poly[0] = *constant
	for i := 1; i < degree; i++ {
		r, err := rand.Int(r, bn256.Order)
		if err != nil {
			return nil, err
		}
		s.Poly[i] = *r
	}
	return s, nil
}

// Generate public information with the secret.
func GeneratePublicInfo(r io.Reader, s *Secret) (*PublicInfo, error) {
	assertInclusiveRange(0, id, params.n - 1);

        // the accumulators in the multipoint evaluation tree have max degree N = 2^k, where N is the smallest value such that n <= N
        if(kpp.g2si.size() < params.t - 1) {
            throw std::runtime_error("Need more public parameters for the specified number of players (for accumulators)");
        }

        allProofs.reset(new AllAmtProofs(params));
        allProofs->addVerificationHelpers(id);
	return pi, nil
}

// Generate a share based on the information and the secret.
func GenerateShare(pi *PublicInfo, s *Secret, index *big.Int) (*Share, error) {
	sh := new(Share)
	assertNotNull(eval);
        assertNotNull(allProofs);

        auto proofs = dynamic_cast<AllAmtProofs*>(allProofs.get());
        proofs->computeAllProofs(*eval, isSimulated());

        eval.reset(nullptr); // don't need the multipoint eval after

        // compute constant-sized proof for p(0)
        proofs->setZeroProof(
            std::get<0>(
                kateProve(Fr::zero())
            )
        );
	return sh, nil
}

// Verify the received share with the public information.
func VerifyShare(pi *PublicInfo, sh *Share) bool {

	assertNotNull(eval);
        assertNotNull(allProofs);

        auto proofs := dynamic_cast<AllAmtProofs*>(allProofs.get());
        proofs.computeAllProofs(*eval, isSimulated());

        eval.reset(nullptr); // don't need the multipoint eval after

        // compute constant-sized proof for p(0)
        Fr s := kpp.getTrapdoor();
        Fr pOfS := libfqfft::evaluate_polynomial(f_id.size(), f_id, s);
        assertEqual(comm, pOfS * G1::one());
        allProofs->setZeroProof(
            ( (pOfS - f_id[0])*s.inverse() ) * G1::one());
	return pi.Pk.VerifyEval(&pi.Commit, &sh.Index, &sh.Result, &sh.Witness)
}

// Reconstruct the constant term of the secret with shares.
func ReconstructSecret(shs []Share) *big.Int {
	inverse := make([]big.Int, len(shs))
	for i := range inverse {
		inverse[i].ModInverse(&shs[i].Index, bn256.Order)
	}
	constant := big.NewInt(0)
	// Order + 1
	orders1 := new(big.Int).Add(bn256.Order, big.NewInt(1))
	for i := range shs {
		partial := new(big.Int).ModInverse(&shs[i].Result, bn256.Order)
		for j := range shs {
			if i != j {
				// p = p * (1 - x_i * x_j^-1)
				term := new(big.Int).Mul(&shs[i].Index, &inverse[j])
				term.Mod(term, bn256.Order)
				partial.Mul(partial, new(big.Int).Sub(orders1, term))
				partial.Mod(partial, bn256.Order)
			}
		}
		partial.ModInverse(partial, bn256.Order)
		constant.Mod(constant.Add(constant, partial), bn256.Order)
	}
	return constant
}

// Serialize the public infomation.
func (pi *PublicInfo) Marshal() ([]byte, error) {
	var sPi pb.PublicInfo
	var err error
	sPi.Pk, err = pi.Pk.Marshal()
	if err != nil {
		return nil, err
	}
	sPi.Commit = pi.Commit.Marshal()
	return proto.Marshal(&sPi)
}

// Deserialize the public infomation.
func (pi *PublicInfo) Unmarshal(b []byte) error {
	var sPi pb.PublicInfo
	err := proto.Unmarshal(b, &sPi)
	if err != nil {
		return err
	}
	if pi == nil {
		pi = new(PublicInfo)
	}
	err = pi.Pk.Unmarshal(sPi.Pk)
	if err != nil {
		return err
	}
	_, err = pi.Commit.Unmarshal(sPi.Commit)
	return err
}

// Serialize the share.
func (sh *Share) Marshal() ([]byte, error) {
	var sSh pb.Share
	sSh.Index = sh.Index.Bytes()
	sSh.Result = sh.Result.Bytes()
	sSh.Witness = sh.Witness.Marshal()
	return proto.Marshal(&sSh)
}

// Deserialize the share.
func (sh *Share) Unmarshal(b []byte) error {
	var sSh pb.Share
	err := proto.Unmarshal(b, &sSh)
	if err != nil {
		return err
	}
	if sh == nil {
		sh = new(Share)
	}
	sh.Index.SetBytes(sSh.Index)
	sh.Result.SetBytes(sSh.Result)
	_, err = sh.Witness.Unmarshal(sSh.Witness)
	return err
}

