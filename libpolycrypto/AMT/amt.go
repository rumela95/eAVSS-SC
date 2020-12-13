
package AMT


struct AllAmtProofs{
        : authAccs(*params.authAccs), n(params.n), numBits(params.numBits), proofNumLevels(params.maxLevel + 1)
}
    
func addVerificationHelpers(size_t id) {
        // Fetch the accumulators needed to verify proofs for p(w_N^id)
        accPathForId = authAccs.getPathFromLeaf(libff::bitreverse(id, numBits));
        accPathForId.resize(proofNumLevels);
    }
    
    func computeAllProofs(const RootsOfUnityEvaluation& eval, bool isSimulated) {
        authEval.reset(new AuthRootsOfUnityEvaluation(eval, authAccs.kpp, isSimulated));
    }

    func setZeroProof(const G1& proof) { f0proof = proof; }

    
    /**
     * Returns the proof for p(w_N^id)
     * NOTE: The AMT proof for p(w_N^id) starts at the root and ends at leaf # bitreverse(id) (i.e., authEval.tree[0][bitreverse(id)])
     * NOTE: We return the proof by value here since it consists of a bunch of quotient commitments from the multipoint eval tree
     */
    func AmtProof getPlayerProof(size_t id) const {
        assertStrictlyLessThan(id, n);

        AmtProof proof;
        proof.quoComms = authEval->getPathFromLeaf(libff::bitreverse(id, numBits));
        proof.quoComms.resize(proofNumLevels);
        return proof;
    }

    /**
     * Verifies an AMT proof for p(id) = val relative to polyComm.
     */
    func verifyAtId(const G1& polyComm, const AmtProof& proof, const Fr& val) bool {
        G1 valComm = val * G1::one();
        logtrace << "Verifying at ID" << endl;
        return verifyCommLogSized(polyComm, proof, valComm, accPathForId);
    }

    /**
     * Verifies a normal Kate et al proof for valComm = g^p_j(0) where p_j is committed in polyComm.
     */
    func verifyAtZero(const G1& polyComm, const G1& proof, const G1& valComm) bool {
        return verifyCommConstSized(polyComm, proof, valComm, authAccs.kpp.getG2toS());
    }

    /**
     * Verifies an AMT proof for valComm = g^p_j(z), where p_j is committed in polyComm and z is a root of a(x), which is committed in accs.
     */
    func verifyCommLogSized(const G1& polyComm, const AmtProof& proof, const G1& valComm, const std::vector<G2>& accs) const {
        GT lhs = ReducedPairing(polyComm - valComm, G2::one());
        GT rhs = GT::one(); // GT uses multiplicative notation

        testAssertEqual(accs.size(), proof.quoComms.size());

        // TODO: could multithread this verification, but libff crashes in ReducedPairing for some reason
        logtrace << "Path height: " << accs.size() << endl;
        for(size_t i = 0; i < accs.size(); i++) {
            logtrace << "q[" << i << "] = " << proof.quoComms[i] << endl;
            logtrace << "a[" << i << "] = " << accs[i] << endl;

            // we remove g^{q(s)}) commitments from the proof when q(s) = 0
            testAssertFalse(proof.quoComms[i] == G1::zero());

            rhs = rhs * ReducedPairing(proof.quoComms[i], accs[i]);
        }

        return lhs == rhs;
    }

    /**
     * Verifies a normal Kate et al proof for valComm = g^p_j(z), where p_j is committed in polyComm and z is committed in acc = g^{s - z}
     */
    func verifyCommConstSized(const G1& polyComm, const G1& proof, const G1& valComm, const G2& acc) const {
        return ReducedPairing(polyComm - valComm, G2::one()) ==
               ReducedPairing(proof, acc);
    }
};

