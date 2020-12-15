package amt

import (
	"crypto/rand"
	"errors"
	"math"
	"math/big"
	"strconv"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/zhtluo/libpolycrypto/polycommit"
)

func allocateTree(numLeaves int, maxLevel int) [][]*big.Int {
	// testAssertIsPowerOfTwo(numLeaves);

	/**
	 * Height of tree in # of levels, where levels are counted as nodes (not as edges)
	 * For example, when numLeaves = 2, height is 2.
	 * Or, when numLeaves = 3 or 4, height is 3.
	 * Or, when numLeaves = 5, 6, 7 or 8, height is 4.
	 * In general, height is ceil(log2(numLeaves)) + 1.
	 */
	maxHeight := math.Log2(float64(numLeaves)) + 1
	maxht := int(maxHeight)
	if maxLevel >= maxht {
		// logerror << "Cannot create tree with max level # " << maxLevel << endl;
		// logerror << "Max possible level # (starting at 0) for tree with " << numLeaves << " leaves is " << maxHeight - 1 << endl;
		// throw std::runtime_error("Invalid max level");
	}

	numLevels := maxLevel + 1
	tree := make([][]*big.Int, numLevels)
	return tree

	// for k := 1; k < numLevels; k++ {
	// 	tree[k] = make([][]*big.Int, len(tree[k-1])/2)
	// }

	// Check the root level has size 1
	// assertEqual(tree[maxLevel].size(), numLeaves / (1u << maxLevel));
}

type PublicInfo = polycommit.Pk_ped

func Expand(cred []big.Int) (poly []big.Int) {
	poly = make([]big.Int, len(cred)+1)
	poly[0].SetInt64(1)
	// Polynomial expansion. Change to FFT if necessary.
	for i := range cred {
		for j := i + 1; j >= 1; j-- {
			poly[j].Sub(&poly[j-1], new(big.Int).Mul(&poly[j], &cred[i]))
		}
		poly[0].Neg(poly[0].Mul(&poly[0], &cred[i]))
	}
	return
}

func Evaluate(pi *PublicInfo, poly []*big.Int) (*bn256.G2, error) {
	return pi.Commit_Ped(poly, poly)
}

func CreateWitness(pi *PublicInfo, poly []big.Int, d *big.Int) (*bn256.G1, error) {
	res, g1, err := CreateWitness_with_amt(poly, d)
	if err != nil {
		return nil, err
	}
	if res.Cmp(big.NewInt(0)) != 0 {
		return nil, errors.New("Polynomial does not contain credential.")
	}
	return g1, nil
}

func Verify(pi *PublicInfo, g2 *bn256.G2, g1 *bn256.G1, d *big.Int) bool {
	return pi.VerifyEval(g2, d, big.NewInt(0), g1)
}

type TreeNode struct {
	Val   int
	Left  *TreeNode
	Right *TreeNode
}

func binaryTreePaths(root *TreeNode) ([]string, *bn256.G1, error) {
	s := []string{}
	if root == nil {
		_, Ga, err := bn256.RandomG1(rand.Reader)
		return s, Ga, err
	}
	helper(root, strconv.Itoa(root.Val), &s)
	_, Ga, err := bn256.RandomG1(rand.Reader)
	return s, Ga, err
}

func helper(node *TreeNode, path string, s *[]string) {
	if node.Left == nil && node.Right == nil {
		*s = append(*s, path)
	}
	if node.Left != nil {
		helper(node.Left, path+"->"+strconv.Itoa(node.Left.Val), s)
	}
	if node.Right != nil {
		helper(node.Right, path+"->"+strconv.Itoa(node.Right.Val), s)
	}

}

func CreateWitness_with_amt(poly []big.Int, d *big.Int) (res *big.Int, g1 *bn256.G1, err error) {
	_, x, err := binaryTreePaths(nil)
	// g1 = new(bn256.G1)
	i := d
	g_i := new(bn256.G2)
	g_i.ScalarBaseMult(i)
	// p := new(bn256.G2)
	return d, x, err

}
