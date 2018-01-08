package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
)

type parameter struct {
	Name        string
	Value       string
	Type        string
	Description string
}

type backup struct {
	NameSpace  string
	Parameters []parameter
}

func (b *backup) writeJSON(f string) {
	respJSON, err := json.Marshal(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(f, respJSON, 0644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func (b *backup) readJSON(f string) {
	fileJSON, err := ioutil.ReadFile(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	err = json.Unmarshal(fileJSON, &b)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func encrypt(text string) string {
	plaintext := []byte(text)

	block, err := aes.NewCipher(key())
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

func key() []byte {
	// this is our encrption key
	//
	// key := []byte(os.Getenv("PBR_KEY"))
	// if os.Getenv("PBR_KEY") == "" {
	// 	fmt.Println("hello")
	// }

	return []byte("123456789012345678901234567adfas")
}

// decrypt from base64 to decrypted string
func decrypt(cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key())
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

func getParameters(s *ssm.SSM, namesp string) backup {
	c := make(chan parameter)
	pbr := backup{}
	pbr.NameSpace = namesp
	input := ssm.DescribeParametersInput{}

	if namesp != "" {
		input = ssm.DescribeParametersInput{
			Filters: []*ssm.ParametersFilter{&ssm.ParametersFilter{
				Key:    aws.String("Name"),
				Values: aws.StringSlice([]string{namesp}),
			}},
		}
	}
	parameters := ssm.DescribeParametersOutput{}
	err := s.DescribeParametersPages(&input,
		func(page *ssm.DescribeParametersOutput, lastPage bool) bool {
			parameters.Parameters = append(parameters.Parameters, page.Parameters...)
			return !lastPage
		})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	names := aws.StringSlice([]string{})
	descriptions := map[string]string{}
	for _, p := range parameters.Parameters {
		names = append(names, p.Name)
		if p.Description != nil {
			descriptions[*p.Name] = *p.Description
		} else {
			descriptions[*p.Name] = ""
		}

	}
	for i := 0; i < len(names); i += 10 {
		// get 10 at a time
		end := i + 10
		if end > len(names) {
			end = len(names)
		}
		//concurrency ftw
		go func(n []*string, i, e int) {
			sp, err := s.GetParameters(&ssm.GetParametersInput{
				Names:          n[i:e],
				WithDecryption: aws.Bool(true),
			})
			if err != nil {
				panic(err)
			}
			for _, p := range sp.Parameters {
				newParameter := parameter{}
				newParameter.Name = *p.Name
				newParameter.Type = *p.Type
				// encrypt if secure string
				if *p.Type == "SecureString" {
					newParameter.Value = encrypt(*p.Value)
				} else {
					newParameter.Value = *p.Value
				}
				newParameter.Description = descriptions[*p.Name]
				c <- newParameter
			}
		}(names, i, end)
	}
	for range names {
		pbr.Parameters = append(pbr.Parameters, <-c)
	}
	return pbr
}

func putParameters(s *ssm.SSM, b backup, ch *int) {
	chunksize := *ch // this is how many request to send at once
	parameters := b.Parameters
	for i := 0; i < len(parameters); i += chunksize {
		wg := sync.WaitGroup{}
		end := i + chunksize
		if end > len(parameters) {
			end = len(parameters)
		}
		for _, p := range parameters[i:end] {
			if p.Type == "SecureString" {
				p.Value = decrypt(p.Value)
			}
			wg.Add(1)
			go func(p parameter, wg *sync.WaitGroup) {
				defer wg.Done()
				_, err := s.PutParameter(&ssm.PutParameterInput{
					Name:        aws.String(p.Name),
					Value:       aws.String(p.Value),
					Type:        aws.String(p.Type),
					Description: aws.String(p.Description),
					Overwrite:   aws.Bool(true), // this should be a flag
				})
				// respJSON, _ := json.Marshal(r)
				// fmt.Println(string(respJSON))

				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}(p, &wg)
		}
		wg.Wait()
		// fmt.Println("Done Batch")
	}
}

func startTimer(name string) func() {
	t := time.Now()
	return func() {
		d := time.Now().Sub(t)
		log.Println(name, "took", d)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `
usage: parameter-restore [flags] [action]

Examples:
Backup: 
	parameter-restore -json-file=output.json backup
	parameter-restore -json-file=output.json -namespace=/Team backup
Restore:
	parameter-restore -json-file=input.json restore
`)
	flag.PrintDefaults()
}

var (
	nameSpace  = flag.String("namespace", "", "Filter for namespace. Same as 'someparameter*'")
	jsonfile   = flag.String("json-file", "", "Path to json file. Used for restore and backup so be careful")
	awsProfile = flag.String("profile", "", "Use a specific profile from your credential file")
	restoreCon = flag.Int("concurrency", 1, "May increase restore speed in some cases")
)

func main() {
	stop := startTimer("pbr")
	defer stop()
	flag.Usage = usage

	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}
	if args[0] != "restore" && args[0] != "backup" {
		fmt.Println("Must specify `restore` or `backup`")
		flag.Usage()
		os.Exit(2)
	}
	if *jsonfile == "" {
		fmt.Println("Missing -json-file")
		flag.Usage()
		os.Exit(2)
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Profile:           *awsProfile,
	}))

	ssmSvc := ssm.New(sess)

	switch args[0] {
	case "restore":
		pbr := backup{}
		pbr.readJSON(*jsonfile)
		putParameters(ssmSvc, pbr, restoreCon)
	case "backup":
		pbr := getParameters(ssmSvc, *nameSpace)
		pbr.writeJSON(*jsonfile)
	}
}
