package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/golang-jwt/jwt/v5"
)

type GraphQLResponse struct {
	Data struct {
		User struct {
			Login       string `json:"login"`
			Name        string `json:"name"`
			AvatarURL   string `json:"avatarUrl"`
			Bio         string `json:"bio"`
			Location    string `json:"location"`
			Company     string `json:"company"`
			Followers   struct{ TotalCount int } `json:"followers"`
			Following   struct{ TotalCount int } `json:"following"`
			Repositories struct {
				TotalCount int `json:"totalCount"`
				Nodes      []struct {
					Name            string `json:"name"`
					Description     string `json:"description"`
					StargazerCount  int    `json:"stargazerCount"`
					PrimaryLanguage struct {
						Name  string `json:"name"`
						Color string `json:"color"`
					} `json:"primaryLanguage"`
					Languages struct {
						Edges []struct {
							Size int `json:"size"`
							Node struct {
								Name  string `json:"name"`
								Color string `json:"color"`
							} `json:"node"`
						} `json:"edges"`
					} `json:"languages"`
				} `json:"nodes"`
			} `json:"repositories"`
		} `json:"user"`
	} `json:"data"`
}

type Language struct {
	Name  string
	Color string
}

type ProcessedUser struct {
	Title       string            `json:"title"`
	Subtitle    string            `json:"subtitle"`
	Bg          string            `json:"bg"`
	Type        []string          `json:"type"`
	Photo       string            `json:"photo"`
	Details     []string          `json:"details"`
	Moves       [][]interface{}   `json:"moves"`
	Stats       [][]string        `json:"stats"`
	Biography   string            `json:"biography"`
	Attribution string            `json:"attribution"`
	Logo        []string          `json:"logo"`
	Count       string            `json:"count"`
	Total       string            `json:"total"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Oh well...")
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("GITHUB_TOKEN not found")
	}
	apiURL := os.Getenv("TARGET_API_URL")
	if apiURL == "" {
		log.Fatal("TARGET_API_URL not found")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" 
		fmt.Println("PORT environment variable not set, using default port 8080")
	}
	http.HandleFunc("/user/", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Invalid or missing Authorization header", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		server_secret := os.Getenv("SERVER_JWT_SECRET")
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(server_secret), nil
		})
		if err != nil {
			http.Error(w, "Invalid JWT token", http.StatusUnauthorized)
			return
		}
		username := r.URL.Path[len("/user/"):]
		if username == "" {
			http.Error(w, "Username is required", http.StatusBadRequest)
			return
		}
		userData, err := fetchUserData(token, username)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error fetching user data: %v", err), http.StatusInternalServerError)
			return
		}
		numberStr := r.URL.Query().Get("number")
		number := "?"
		if numberStr != "" {
			var err error
			_, err = strconv.Atoi(numberStr)
			if err != nil {
				http.Error(w, "Invalid multiplier value", http.StatusBadRequest)
				return
			}
			number = numberStr
		}
		processedUser := processUser(userData, number)
		target_alg := os.Getenv("TARGET_API_JWT_ALG")
		target_issuer := os.Getenv("TARGET_API_JWT_ISSUER")
		target_secret := os.Getenv("TARGET_API_JWT_SECRET")
		jwtToken, err := generateJWT(target_alg, target_issuer, target_secret)
		if err != nil {
			http.Error(w, "Failed to generate JWT token", http.StatusInternalServerError)
			return
		}
		response, err := postToTargetAPI(apiURL, processedUser, jwtToken)
		if err != nil {
			http.Error(w, "Failed to get image. "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(response)
	})
	fmt.Println("Server is running on port "+port+"...")
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func generateJWT(alg string, issuer string, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod(alg), jwt.MapClaims{
		"iss": issuer,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	return token.SignedString([]byte(secret))
}

func fetchUserData(token, username string) (*GraphQLResponse, error) {
	query := `
		query($username: String!) {
			user(login: $username) {
				login
				name
				avatarUrl
				bio
				location
				company
				followers {
					totalCount
				}
				following {
					totalCount
				}
				repositories(first: 100, orderBy: {field: STARGAZERS, direction: DESC}) {
					totalCount
					nodes {
						name
						description
						stargazerCount
						primaryLanguage {
							name
							color
						}
						languages(first: 10) {
							edges {
								size
								node {
									name
									color
								}
							}
						}
					}
				}
			}
		}`
	payload := map[string]interface{}{
		"query": query,
		"variables": map[string]string{
			"username": username,
		},
	}
	payloadBytes, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", "https://api.github.com/graphql", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var graphqlResp GraphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&graphqlResp); err != nil {
		return nil, err
	}
	return &graphqlResp, nil
}

func processUser(data *GraphQLResponse, number string) ProcessedUser {
	user := data.Data.User
	var repoName1, repoDesc1, repoURL1 string
	var repoStarCount1 string
	var repoLanguagesNames1 []string
	var repoLanguagesColors1 []string
	var repoName2, repoDesc2, repoURL2 string
	var repoStarCount2 string
	var repoLanguagesNames2 []string
	var repoLanguagesColors2 []string
	if len(user.Repositories.Nodes) > 0 {
		repo1 := user.Repositories.Nodes[0]
		repoName1 = repo1.Name
		repoDesc1 = repo1.Description
		repoURL1 = fmt.Sprintf("https://github.com/%s/%s", user.Login, repo1.Name)
		repoStarCount1 = strconv.Itoa(repo1.StargazerCount)
		for i, lang := range repo1.Languages.Edges {
			if i >= 4 {
        		break
    		}
			if lang.Node.Name != "" && lang.Node.Color != "" {
				repoLanguagesNames1 = append(repoLanguagesNames1, lang.Node.Name)
				repoLanguagesColors1 = append(repoLanguagesColors1, lang.Node.Color)
			}
		}
	}
	if len(user.Repositories.Nodes) > 1 {
		repo2 := user.Repositories.Nodes[1]
		repoName2 = repo2.Name
		repoDesc2 = repo2.Description
		repoURL2 = fmt.Sprintf("https://github.com/%s/%s", user.Login, repo2.Name)
		repoStarCount2 = strconv.Itoa(repo2.StargazerCount)
		for i, lang := range repo2.Languages.Edges {
			if i >= 4 {
        		break
    		}
			if lang.Node.Name != "" && lang.Node.Color != "" {
				repoLanguagesNames2 = append(repoLanguagesNames2, lang.Node.Name)
				repoLanguagesColors2 = append(repoLanguagesColors2, lang.Node.Color)
			}
		}
	}
	counts := make(map[Language]int)
	mostUsedLanguage := Language{}
	maxCount := 0
	for _, repo := range user.Repositories.Nodes {
		for _, edge := range repo.Languages.Edges {
			currentLang := Language{
				Name:  edge.Node.Name,
				Color: edge.Node.Color,
			}
			counts[currentLang] += edge.Size
			if counts[currentLang] >= maxCount {
				mostUsedLanguage = currentLang
				maxCount = counts[currentLang]
			}
		}
	}
	var repoCount = strconv.Itoa(user.Repositories.TotalCount)
	var followingCount = strconv.Itoa(user.Following.TotalCount)
	var followersCount = strconv.Itoa(user.Following.TotalCount)
	return ProcessedUser{
		Title:                defaultIfEmpty(user.Name, user.Login),
		Subtitle:             fmt.Sprintf("https://github.com/%s", user.Login),
		Bg:                   mostUsedLanguage.Color,
		Type:                 []string{mostUsedLanguage.Name, mostUsedLanguage.Color},
		Photo:                user.AvatarURL,
		Details:              []string{"GitHub User.", defaultIfEmpty(user.Location, "Unknown Location")+".", defaultIfEmpty(user.Company, "Unknown Company")+"."},
		Moves:                [][]interface{}{
			{
				mapToEmptyIfNil(repoLanguagesNames1),
				mapToEmptyIfNil(repoLanguagesColors1),
				[]interface{}{repoName1, repoURL1, repoDesc1},
				repoStarCount1,
			},
			{
				mapToEmptyIfNil(repoLanguagesNames2),
				mapToEmptyIfNil(repoLanguagesColors2),
				[]interface{}{repoName2, repoURL2, repoDesc2},
				repoStarCount2,
			},
		},
		Stats:                [][]string{{"repos", repoCount},{"following",followingCount},{"followers",followersCount}},
		Biography:            defaultIfEmpty(user.Bio, "We don't know much about "+defaultIfEmpty(user.Name, user.Login)+", but we heard they are pretty cool."),
		Attribution:          "Generated using public data sourced from GitHub",
		Logo:                 []string{"https://i.imgur.com/vdXGhxq.png", "GH"},
		Count:                number,
		Total:                "∞",
	}
}

func defaultIfEmpty(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func mapToEmptyIfNil(input []string) []string {
	if input == nil {
		return []string{}
	}
	return input
}

func postToTargetAPI(apiURL string, data interface{}, jwtToken string) ([]byte, error) {
	payloadBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwtToken))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "image/png" {
		return nil, fmt.Errorf("unexpected content type: %s", resp.Header.Get("Content-Type"))
	}
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return responseBody, nil
}