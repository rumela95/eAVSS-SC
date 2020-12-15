package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"time"

	// "github.com/cloudflare/bn256"

	"github.com/perlin-network/noise"
	"github.com/perlin-network/noise/kademlia"
	"github.com/spf13/pflag"
	"github.com/zhtluo/libpolycrypto/eavss"
	"github.com/zhtluo/libpolycrypto/eavss_amt"
)

var (
	hostFlag    = pflag.IPP("host", "h", nil, "binding host")
	portFlag    = pflag.Uint16P("port", "p", 0, "binding port")
	addressFlag = pflag.StringP("address", "a", "", "publicly reachable network address")
	snd_c       = 0
	rds_c       = 0
	eco_c       = 0
	rd          = 0
)
var node *noise.Node
var overlay *kademlia.Protocol
var noOfNodes int
var t int

type chatMessage struct {
	contents string
}

func (m chatMessage) Marshal() []byte {
	return []byte(m.contents)
}

func unmarshalChatMessage(buf []byte) (chatMessage, error) {
	return chatMessage{contents: strings.ToValidUTF8(string(buf), "")}, nil
}

// check panics if err is not nil.
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// printedLength is the total prefix length of a public key associated to a chat users ID.
const printedLength = 8

// An example chat application on Noise.
func main() {
	// Parse flags/options.
	pflag.Parse()

	// Create a new configured node.
	n, err := noise.NewNode(
		noise.WithNodeBindHost(*hostFlag),
		noise.WithNodeBindPort(*portFlag),
		noise.WithNodeAddress(*addressFlag),
	)
	node = n
	check(err)

	// Release resources associated to node at the end of the program.
	defer node.Close()

	// Register the chatMessage Go type to the node with an associated unmarshal function.
	node.RegisterMessage(chatMessage{}, unmarshalChatMessage)

	// Register a message handler to the node.
	node.Handle(handle)

	// Instantiate Kademlia.
	events := kademlia.Events{
		OnPeerAdmitted: func(id noise.ID) {
			fmt.Printf("Learned about a new peer %s(%s).\n", id.Address, id.ID.String()[:printedLength])
		},
		OnPeerEvicted: func(id noise.ID) {
			fmt.Printf("Forgotten a peer %s(%s).\n", id.Address, id.ID.String()[:printedLength])
		},
	}

	overlay = kademlia.New(kademlia.WithProtocolEvents(events))

	// Bind Kademlia to the node.
	node.Bind(overlay.Protocol())

	// Have the node start listening for new peers.
	check(node.Listen())

	// Print out the nodes ID and a help message comprised of commands.
	help(node)

	// Ping nodes to initially bootstrap and discover peers from.
	bootstrap(node, pflag.Args()...)

	// Attempt to discover peers if we are bootstrapped to any nodes.
	discover(overlay)

	// Accept chat message inputs and handle chat commands in a separate goroutine.
	go input(func(line string) {
		chat(node, overlay, line)
	})

	// Wait until Ctrl+C or a termination call is done.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	// Close stdin to kill the input goroutine.
	check(os.Stdin.Close())

	// Empty println.
	println()
}

// input handles inputs from stdin.
func input(callback func(string)) {
	r := bufio.NewReader(os.Stdin)

	for {
		buf, _, err := r.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}

			check(err)
		}

		line := string(buf)
		if len(line) == 0 {
			continue
		}

		callback(line)
	}
}

// handle handles and prints out valid chat messages from peers.
func handle(ctx noise.HandlerContext) error {
	if ctx.IsRequest() {
		return nil
	}

	obj, err := ctx.DecodeMessage()
	if err != nil {
		return nil
	}

	msg, ok := obj.(chatMessage)
	if !ok {
		return nil
	}

	// if msg == nil {
	// 	fmt.Printf("Nothing from eavss\n")
	// 	return nil
	// }
	mt := strings.Split(msg.contents, "@")
	if mt[1] == "SND" {
		sendReceived(ctx, msg.contents)
	} else if mt[1] == "ECO" {
		ecoReceived(ctx, msg.contents)
	} else if mt[1] == "RDS" {
		if rd > 0 {
			rdyReceived(ctx, msg.contents)

		} else {
			sndRdy(ctx, msg.contents)
		}

	}

	// fmt.Printf("%s(%s)> %s\n", ctx.ID().Address, ctx.ID().ID.String()[:printedLength], msg.contents)

	return nil
}

func sendReceived(ctx noise.HandlerContext, m string) {
	snd_c = snd_c + 1
	// ids := overlay.Table().Peers()
	// count := len(ids)
	fmt.Printf("%s(%s)> %s\n", ctx.ID().Address, ctx.ID().ID.String()[:printedLength], m)
	// sh := eavss.EavssSC(big.NewInt(int64(count)))
	//verify
	echo_m := "ECO"
	k := 0
	for _, id := range overlay.Table().Peers() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		// x := eachshare{mtype: "SND",
		// 	CP:     sh.CP,
		// 	C:      sh.C,
		// 	W:      sh.W[k],
		// 	polyH:  sh.PolyH,
		// 	polyK1: sh.PolyK1[k],
		// 	polyK2: sh.PolyK2[k]}
		// msg, _ := JSON.Marshal(x)
		line := fmt.Sprintf("%d@%s", k, echo_m)
		fmt.Println(line)
		err := node.SendMessage(ctx, id.Address, chatMessage{contents: line})
		cancel()
		k = k + 1

		if err != nil {
			fmt.Printf("Failed to send message to %s(%s). Skipping... [error: %s]\n",
				id.Address,
				id.ID.String()[:printedLength],
				err,
			)
			continue
		}
	}
	fmt.Println("Echo messages sent")

}

func ecoReceived(ctx noise.HandlerContext, m string) {
	eco_c = eco_c + 1

	fmt.Printf("%s(%s)> %s\n", ctx.ID().Address, ctx.ID().ID.String()[:printedLength], m)
	if eco_c >= noOfNodes-t {
		ready_m := "RDS"
		k := 0
		for _, id := range overlay.Table().Peers() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			// x := eachshare{mtype: "SND",
			// 	CP:     sh.CP,
			// 	C:      sh.C,
			// 	W:      sh.W[k],
			// 	polyH:  sh.PolyH,
			// 	polyK1: sh.PolyK1[k],
			// 	polyK2: sh.PolyK2[k]}
			// msg, _ := JSON.Marshal(x)
			line := fmt.Sprintf("%d@%s", k, ready_m)
			err := node.SendMessage(ctx, id.Address, chatMessage{contents: line})
			cancel()
			k = k + 1

			if err != nil {
				fmt.Printf("Failed to send message to %s(%s). Skipping... [error: %s]\n",
					id.Address,
					id.ID.String()[:printedLength],
					err,
				)
				continue
			}
		}
		rd = rd + 1
		fmt.Println("Ready message sent")
	} else {
		fmt.Println("Waiting for n-t echo messages..")
	}

}

func rdyReceived(ctx noise.HandlerContext, m string) {
	rds_c = rds_c + 1

	fmt.Printf("%s(%s)> %s\n", ctx.ID().Address, ctx.ID().ID.String()[:printedLength], m)
	if rds_c >= noOfNodes-t {
		rec_m := "REC"
		k := 0
		for _, id := range overlay.Table().Peers() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			// x := eachshare{mtype: "SND",
			// 	CP:     sh.CP,
			// 	C:      sh.C,
			// 	W:      sh.W[k],
			// 	polyH:  sh.PolyH,
			// 	polyK1: sh.PolyK1[k],
			// 	polyK2: sh.PolyK2[k]}
			// msg, _ := JSON.Marshal(x)
			line := fmt.Sprintf("%d@%s", k, rec_m)
			err := node.SendMessage(ctx, id.Address, chatMessage{contents: line})
			cancel()
			k = k + 1

			if err != nil {
				fmt.Printf("Failed to send message to %s(%s). Skipping... [error: %s]\n",
					id.Address,
					id.ID.String()[:printedLength],
					err,
				)
				continue
			}
		}
		rd = rd + 1
		fmt.Println("Sharing Phase complete")
	} else {
		fmt.Println("Waiting for n-t ready messages..")
	}

}

func sndRdy(ctx noise.HandlerContext, m string) {
	rds_c = rds_c + 1

	fmt.Printf("%s(%s)> %s\n", ctx.ID().Address, ctx.ID().ID.String()[:printedLength], m)
	if rds_c >= noOfNodes-t {
		ready_m := "RDS"
		k := 0
		for _, id := range overlay.Table().Peers() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			// x := eachshare{mtype: "SND",
			// 	CP:     sh.CP,
			// 	C:      sh.C,
			// 	W:      sh.W[k],
			// 	polyH:  sh.PolyH,
			// 	polyK1: sh.PolyK1[k],
			// 	polyK2: sh.PolyK2[k]}
			// msg, _ := JSON.Marshal(x)
			line := fmt.Sprintf("%d@%s", k, ready_m)
			err := node.SendMessage(ctx, id.Address, chatMessage{contents: line})
			cancel()
			k = k + 1

			if err != nil {
				fmt.Printf("Failed to send message to %s(%s). Skipping... [error: %s]\n",
					id.Address,
					id.ID.String()[:printedLength],
					err,
				)
				continue
			}
		}
		rd = rd + 1
		fmt.Println("Ready Message sent")
	} else {
		fmt.Println("Waiting for n-t ready messages..")
	}

}

// help prints out the users ID and commands available.
func help(node *noise.Node) {
	fmt.Printf("Your ID is %s(%s). Type '/discover' to attempt to discover new "+
		"peers, or '/peers' to list out all peers you are connected to.\n",
		node.ID().Address,
		node.ID().ID.String()[:printedLength],
	)
}

// bootstrap pings and dials an array of network addresses which we may interact with and  discover peers from.
func bootstrap(node *noise.Node, addresses ...string) {
	for _, addr := range addresses {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := node.Ping(ctx, addr)
		cancel()

		if err != nil {
			fmt.Printf("Failed to ping bootstrap node (%s). Skipping... [error: %s]\n", addr, err)
			continue
		}
	}
}

// discover uses Kademlia to discover new peers from nodes we already are aware of.
func discover(overlay *kademlia.Protocol) {
	ids := overlay.Discover()

	var str []string
	for _, id := range ids {
		str = append(str, fmt.Sprintf("%s(%s)", id.Address, id.ID.String()[:printedLength]))
	}

	if len(ids) > 0 {
		fmt.Printf("Discovered %d peer(s): [%v]\n", len(ids), strings.Join(str, ", "))
	} else {
		fmt.Printf("Did not discover any peers.\n")
	}
}

// peers prints out all peers we are already aware of.
func peers(overlay *kademlia.Protocol) {
	ids := overlay.Table().Peers()

	var str []string
	for _, id := range ids {
		str = append(str, fmt.Sprintf("%s(%s)", id.Address, id.ID.String()[:printedLength]))
	}

	fmt.Printf("You know %d peer(s): [%v]\n", len(ids), strings.Join(str, ", "))
}

// peers prints out all peers we are already aware of.
func startEavssSC(overlay *kademlia.Protocol, node *noise.Node) {
	ids := overlay.Table().Peers()
	count := len(ids)
	noOfNodes = count
	t = (noOfNodes - 1) / 3
	fmt.Println("Now eavss")
	sh := eavss.EavssSC(big.NewInt(int64(count)))
	k := 0
	// var x pb.Eachshare
	for _, id := range overlay.Table().Peers() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		// x := eavss.Eachshare{Mtype: "SND",
		// 	CP:     sh.CP,
		// 	C:      sh.C,
		// 	W:      sh.W[k],
		// 	PolyH:  sh.PolyH,
		// 	PolyK1: sh.PolyK1[k],
		// 	PolyK2: sh.PolyK2[k]}
		// msg, _ := proto.Marshal(x)
		line := fmt.Sprintf("%d@%s", k, sh.Mtype)
		err := node.SendMessage(ctx, id.Address, chatMessage{contents: line})
		cancel()
		k = k + 1

		if err != nil {
			fmt.Printf("Failed to send message to %s(%s). Skipping... [error: %s]\n",
				id.Address,
				id.ID.String()[:printedLength],
				err,
			)
			continue
		}
	}
	// fmt.Println("Now complete")

}

func startEavssSCAMT(overlay *kademlia.Protocol, node *noise.Node) {
	ids := overlay.Table().Peers()
	count := len(ids)
	noOfNodes = count
	t = (noOfNodes - 1) / 3
	fmt.Println("Now eavss-SC")
	sh := eavss_amt.EavssSCAMT(big.NewInt(int64(count)))
	k := 0
	// var x pb.Eachshare
	for _, id := range overlay.Table().Peers() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		line := fmt.Sprintf("%d@%s", k, sh.Mtype)
		err := node.SendMessage(ctx, id.Address, chatMessage{contents: line})
		cancel()
		k = k + 1

		if err != nil {
			fmt.Printf("Failed to send message to %s(%s). Skipping... [error: %s]\n",
				id.Address,
				id.ID.String()[:printedLength],
				err,
			)
			continue
		}
	}
	// fmt.Println("Now complete")

}

// chat handles sending chat messages and handling chat commands.
func chat(node *noise.Node, overlay *kademlia.Protocol, line string) {
	switch line {
	case "/discover":
		discover(overlay)
		return
	case "/start":
		startEavssSC(overlay, node)
		return
	case "/startAMT":
		startEavssSCAMT(overlay, node)
		return
	case "/peers":
		peers(overlay)
		return
	default:
	}

	if strings.HasPrefix(line, "/") {
		help(node)
		return
	}

	for _, id := range overlay.Table().Peers() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := node.SendMessage(ctx, id.Address, chatMessage{contents: line})
		cancel()

		if err != nil {
			fmt.Printf("Failed to send message to %s(%s). Skipping... [error: %s]\n",
				id.Address,
				id.ID.String()[:printedLength],
				err,
			)
			continue
		}
	}
}
