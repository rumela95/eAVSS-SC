package eavss

import (
	"fmt"

	"crypto/rand"
	"io"
	"math/big"

	hmap "github.com/cloudflare/bn256"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/zhtluo/libpolycrypto/polycommit"
)

// type Pk_ped struct {
// 	G1P []bn256.G1
// 	G2P []bn256.G2
// 	G2H []bn256.G2
// }
type eachshare struct {
	mtype  string      `json:"mtype"`
	ind    int         `json:"ind"`
	CP     *bn256.G2   `json:"CP"`
	C      []*bn256.G2 `json:"C"`
	W      []*bn256.G1 `json:"W"`
	polyH  []*big.Int  `json:"polyH"`
	polyK1 []*big.Int  `json:"polyK1"`
	polyK2 []*big.Int  `json:"polyK2"`
}

type ready struct {
	mtype string    `json:"mtype"`
	ind   int       `json:"ind"`
	CP    *bn256.G2 `json:"CP"`
}

type echo struct {
	mtype string    `json:"mtype"`
	CP    *bn256.G2 `json:"CP"`
}

type share struct {
	mtype  string
	Pk     polycommit.Pk_ped
	CP     *bn256.G2
	C      []*bn256.G2
	W      [][]*bn256.G1
	polyH  []*big.Int
	polyK1 [][]*big.Int
	polyK2 [][]*big.Int
}

// const (
// 	deg = 3
// )

// func generatePolyX(r io.Reader) []big.Int {
// 	poly := make([]big.Int, deg+1)
// 	for i, _ := range poly {
// 		var p *big.Int
// 		p, _ = rand.Int(r, bn256.Order)
// 		poly[i] = *p
// 		bigstr := fmt.Sprint(poly[i])
// 		fmt.Println(bigstr)
// 	}
// 	return poly
// }

func generatePoly(r io.Reader, deg int) []*big.Int {
	poly := make([]*big.Int, deg)
	for i, _ := range poly {
		var p *big.Int
		p, _ = rand.Int(r, bn256.Order)
		poly[i] = &*p
		bigstr := fmt.Sprint(*poly[i])
		fmt.Println(bigstr)
	}
	return poly
}

func generateYPoly(poly []*big.Int) []*big.Int {
	polyY := poly
	return polyY
}

func valueOfPoly(poly []*big.Int, i *big.Int) *big.Int {
	res := new(big.Int)
	for i, _ := range poly {
		x2 := big.NewInt(int64(i))
		for j := 2; j < i; j++ {
			x2.Mul(x2, x2)
		}
		res.Add(res, poly[i].Mul(poly[i], x2))
	}

	return res

}

// func EavssSC(n *big.Int) *share {
func EavssSC(n *big.Int) {
	t := n.Div(n.Sub(n, big.NewInt(1)), big.NewInt(3))
	polyP := generatePoly(rand.Reader, int(t.Int64())+1)
	polyC := generatePoly(rand.Reader, int(t.Int64())+1)
	PolyPY := generateYPoly(polyP)
	PolyCY := generateYPoly(polyC)
	polyK1 := make([][]*big.Int, n.Int64())
	polyK2 := make([][]*big.Int, n.Int64())
	W := make([][]*bn256.G1, n.Int64())
	var pk1, pk2 polycommit.Pk_ped
	C := make([]*bn256.G2, n.Int64())
	H := make([]*hmap.G1, n.Int64())
	pk1.Setup2(rand.Reader, int(t.Int64())+1)
	pk2.Setup2(rand.Reader, int(n.Int64())+1)
	no_pl := int(n.Int64())
	for j := 0; j < no_pl; j++ {
		polyP[0] = valueOfPoly(PolyPY, big.NewInt(int64(j)))
		K1 := polyP
		polyK1[j] = K1
		polyC[0] = valueOfPoly(PolyCY, big.NewInt(int64(j)))
		K2 := polyC
		polyK2[j] = K2
		C[j], _ = pk1.Commit_Ped(K1, K2)
		if C[j] != nil {
			fmt.Println(C[j].String())
		} else {
			fmt.Println("hello")

		}
		Wt := make([]*bn256.G1, n.Int64())
		for k := 0; k < no_pl; k++ {
			res1, res2, g1, _ := pk1.CreateWitness_ped(K1, K2, big.NewInt(int64(k)))
			Wt[k] = g1
			if g1 != nil {
				printbig(res1)
				printbig(res2)
				fmt.Println(g1.String())
			}
		}
		W[j] = Wt
		if C[j] != nil {
			x := C[j].Marshal()
			// H[j] = hmap.HashG1(x, nil)
			H[j] = hmap.HashG1(x, nil)
		}
	}
	polyH := generatePoly(rand.Reader, int(n.Int64())+1)
	polyHX := generatePoly(rand.Reader, int(n.Int64())+1)
	CP, _ := pk2.Commit_Ped(polyHX, polyH)
	if CP != nil {
		fmt.Println(CP.String())
	} else {
		fmt.Println("hello")

	}
	// mtype := "SND"
	// return &share{
	// 	mtype,
	// 	pk1,
	// 	CP,
	// 	C,
	// 	W,
	// 	polyH,
	// 	polyK1,
	// 	polyK2}
}

func printbig(k *big.Int) {
	bigstr := fmt.Sprint(k)
	fmt.Println(bigstr)
}

func VerifyShare(pi *polycommit.Pk_ped, sh *eachshare) bool {
	for i, _ := range sh.W {
		if !pi.VerifyEval(sh.C[i], big.NewInt(int64(sh.ind)), valueOfPoly(sh.polyK1, big.NewInt(int64(sh.ind))), sh.W[i]) {
			fmt.Println("verify failed")
		}

	}
	return true
	// return pi.VerifyEval(&sh.C, &sh.ind, valueOfPoly(sh.polyK1, &sh.ind), &sh.W)
}

// func main() {
// 	// *testing.T t

// 	// var x, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
// 	// var y, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689034329847938743243", 10)

// 	// fmt.Println(BigIntToHexStr(x))
// 	// fmt.Println(BigIntToStr(x))

// 	// pt := bigPoint{x, y}
// 	// strPt := strBigPoint{fmt.Sprintf("%v", x), fmt.Sprintf("%v", y)}

// 	// objPt, err := json.Marshal(pt)
// 	// if err != nil {
// 	// 	panic(fmt.Errorf("could not serialize pt to json"))
// 	// }

// 	// objStrPt, err := json.Marshal(strPt)
// 	// if err != nil {
// 	// 	panic(fmt.Errorf("could not serialize strPt to json"))
// 	// }

// 	// fmt.Printf("%v\n", string(objPt))
// 	// fmt.Printf("%v\n", string(objStrPt))

// 	var pk polycommit.Pk
// 	pk.Setup(rand.Reader, deg+1)
// 	poly := generatePolyX(rand.Reader)
// 	g2, _ := pk.Commit(poly)
// 	if g2 != nil {
// 		fmt.Println(g2.String())
// 	} else {
// 		fmt.Println("hello1")

// 	}

// 	// if err != nil {
// 	// 	// t.Error(err.Error())
// 	// 	fmt.Println(err.Error())
// 	// }
// 	// // flag := pk.VerifyPoly(poly, g2)
// 	// if flag != true {
// 	// 	// t.Error("VerifyPoly failed, expected: true.")
// 	// }
// 	// poly = generatePoly(rand.Reader)
// 	// // flag = pk.VerifyPoly(poly, g2)
// 	// if flag != false {
// 	// 	// t.Error("VerifyPoly failed, expected: false.")
// 	// }

// 	fmt.Println("Now eavss")
// 	eavss_sc(big.NewInt(int64(10)))
// 	fmt.Println("Now complete")

// }
