package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "strconv"
    "strings"
    "time"
)

// Structs for JSON marshaling/unmarshaling
type IncidentFilter struct {
    Select []string `json:"select"`
    Where  string   `json:"where"`
}

type IncidentRequest struct {
    Offset         int            `json:"offset"`
    Limit          int            `json:"limit"`
    TimeFrom       string         `json:"timeFrom"`
    FilterTimeType string         `json:"filterTimeType"`
    Filter         IncidentFilter `json:"filter"`
}

type TransitionRequest struct {
    ID       string `json:"id"`
    Measures string `json:"measures"`
    Message  string `json:"message"`
}

type Targets struct {
    Groups   []string `json:"groups"`
    Assets   []string `json:"assets"`
    Networks []string `json:"networks"`
    Addresses []string `json:"addresses"`
    Others   []string `json:"others"`
}

type IncidentDetail struct {
    Key        string      `json:"key"`
    Name       string      `json:"name"`
    Source     string      `json:"source"`
    Detected   string      `json:"detected"`
    Type       string      `json:"type"`
    Severity   string      `json:"severity"`
    Targets    Targets     `json:"targets"`
    Attackers  Targets     `json:"attackers"`
    Description string     `json:"description"`
    Groups     []string    `json:"groups"`
    Influence  string      `json:"influence"`
    Parameters interface{} `json:"parameters"`
}

type IncidentUpdate struct {
    Assigned    string      `json:"assigned"`
    Attackers   Targets     `json:"attackers"`
    Description string      `json:"description"`
    Detected    string      `json:"detected"`
    Groups      []string    `json:"groups"`
    Influence   string      `json:"influence"`
    Name        string      `json:"name"`
    Parameters  interface{} `json:"parameters"`
    Severity    string      `json:"severity"`
    Source      string      `json:"source"`
    Targets     Targets     `json:"targets"`
    Type        string      `json:"type"`
}

type IncidentResponse struct {
    Incidents []struct {
	ID string `json:"id"`
    } `json:"incidents"`
}

func main() {
    if len(os.Args) < 2 || os.Args[1] == "--help" {
	printHelp()
	return
    }

    // Validate arguments
    if len(os.Args) < 5 {
	fmt.Println("Error: Missing required arguments")
	printHelp()
	os.Exit(1)
    }

  host := os.Args[1]
    token := os.Args[2]
    corname := os.Args[3]
    action := os.Args[4]
    message := os.Args[5]

    // Set default limit
    limit := 999
    if len(os.Args) > 5 && os.Args[5] != "" {
	var err error
	limit, err = strconv.Atoi(os.Args[5])
	if err != nil {
	    fmt.Printf("Error: Invalid limit '%s', using default 999\n", os.Args[5])
	    limit = 999
	}
    }

    // Set assigned (optional)
    assigned := ""
    if len(os.Args) > 6 {
	assigned = os.Args[6]
    }

    // Validate no spaces in token or corname
    if strings.Contains(token, " ") || strings.Contains(corname, " ") {
	fmt.Println("Error: No space available in token or correlation name")
	os.Exit(1)
    }

    // Validate action
    validActions := map[string]bool{
	"Closed":     true,
	"Approved":   true,
	"InProgress": true,
	"Resolved":   true,
    }
    if !validActions[action] {
	fmt.Println("Error: Incorrect action. Must be one of: Closed, Approved, InProgress, Resolved")
	os.Exit(1)
    }

    // Get current date in required format
    curdate := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

    // Execute the main logic
    if err := processIncidents(host, token, corname, action, message, limit, assigned, curdate); err != nil {
	fmt.Printf("Error: %v\n", err)
	os.Exit(1)
    }
}

func printHelp() {
    fmt.Println("Usage:")
    fmt.Println("  siem-tool \"param1\" \"param2\" \"param3\" \"param4\" \"param5\" \"param6\" \"param7\"")
    fmt.Println("  'param1' is a hostname")
    fmt.Println("  'param2' is an api token")
    fmt.Println("  'param3' is a correlation name of the incident(s) (example: Unix_Systemd_Service_Modify)")
    fmt.Println("  'param4' is an action (Closed, Approved, InProgress or Resolved)")
    fmt.Println("  'param5' is a comment")
    fmt.Println("  'param6' is a limit of incidents to get (0-999, default 999)")
    fmt.Println("  'param7' is an assignee (UUID, example: 107dd2cd-4ac2-4af5-8c3e-9feec2fcd74c)")
}

func processIncidents(host, token, corname, action, message string, limit int, assigned, curdate string) error {
    // Step 1: Get incident IDs
    ids, err := getIncidentIDs(host, token, corname, limit, curdate)
    if err != nil {
	return fmt.Errorf("failed to get incident IDs: %v", err)
    }

    fmt.Printf("Found %d incident(s)\n", len(ids))

    // Step 2: Process each incident
    for _, id := range ids {
	if err := processIncident(host, token, id, action, message, assigned); err != nil {
	    fmt.Printf("Failed to process incident %s: %v\n", id, err)
	    continue
	}
    }

    return nil
}

func getIncidentIDs(host, token, corname string, limit int, curdate string) ([]string, error) {
    // Prepare request data
    reqData := IncidentRequest{
	Offset:         0,
	Limit:          limit,
	TimeFrom:       curdate,
	FilterTimeType: "creation",
	Filter: IncidentFilter{
	    Select: []string{"key", "name", "category", "type", "status", "created", "assigned"},
	    Where:  fmt.Sprintf("CorrelationNames = '%s' and status = new", corname),
	},
    }

    jsonData, err := json.Marshal(reqData)
    if err != nil {
	return nil, fmt.Errorf("failed to marshal request data: %v", err)
    }

    // Create HTTP request
  url := fmt.Sprintf("https://%s/api/v2/incidents", host)
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
	return nil, fmt.Errorf("failed to create request: %v", err)
    }

    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")

    // Execute request
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
	return nil, fmt.Errorf("failed to execute request: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
	body, _ := io.ReadAll(resp.Body)
	return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
    }

    // Parse response
    var incidentResp IncidentResponse
    if err := json.NewDecoder(resp.Body).Decode(&incidentResp); err != nil {
	return nil, fmt.Errorf("failed to parse response: %v", err)
    }

    // Extract IDs
    ids := make([]string, len(incidentResp.Incidents))
    for i, incident := range incidentResp.Incidents {
	ids[i] = incident.ID
    }

    return ids, nil
}

func processIncident(host, token, id, action, message, assigned string) error {
    // Step 1: Get incident details
    incident, err := getIncidentDetails(host, token, id)
    if err != nil {
	return fmt.Errorf("failed to get incident details: %v", err)
    }

    // Step 2: Update incident
    if err := updateIncident(host, token, id, incident, assigned); err != nil {
	return fmt.Errorf("failed to update incident: %v", err)
    }

    // Step 3: Perform transition
    if err := performTransition(host, token, id, action, message); err != nil {
	return fmt.Errorf("failed to perform transition: %v", err)
    }

    fmt.Printf("Processed %s - https://%s/#/incident/incidents/view/%s\n", incident.Key, host, id)
    return nil
}

func getIncidentDetails(host, token, id string) (*IncidentDetail, error) {
    req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/api/incidentsReadModel/incidents/%s", host, id), nil)
    if err != nil {
	return nil, fmt.Errorf("failed to create request: %v", err)
    }

    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
	return nil, fmt.Errorf("failed to execute request: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
	body, _ := io.ReadAll(resp.Body)
	return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
    }

    var incident IncidentDetail
    if err := json.NewDecoder(resp.Body).Decode(&incident); err != nil {
	return nil, fmt.Errorf("failed to parse incident details: %v", err)
    }

    return &incident, nil
}

func updateIncident(host, token, id string, incident *IncidentDetail, assigned string) error {
    updateData := IncidentUpdate{
	Assigned:    assigned,
	Attackers:   incident.Attackers,
	Description: incident.Description,
	Detected:    incident.Detected,
	Groups:      incident.Groups,
	Influence:   incident.Influence,
	Name:        incident.Name,
	Parameters:  incident.Parameters,
	Severity:    incident.Severity,
	Source:      incident.Source,
	Targets:     incident.Targets,
	Type:        incident.Type,
    }

    jsonData, err := json.Marshal(updateData)
    if err != nil {
	return fmt.Errorf("failed to marshal update data: %v", err)
    }

    req, err := http.NewRequest("PUT", fmt.Sprintf("https://%s/api/incidents/%s", host, id), bytes.NewBuffer(jsonData))
    if err != nil {
	return fmt.Errorf("failed to create update request: %v", err)
    }

    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
	return fmt.Errorf("failed to execute update request: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("update API returned status %d: %s", resp.StatusCode, string(body))
    }

    return nil
}

func performTransition(host, token, id, action, message string) error {
    transitionData := TransitionRequest{
	ID:       action,
	Measures: "",
	Message:  message,
    }

    jsonData, err := json.Marshal(transitionData)
    if err != nil {
	return fmt.Errorf("failed to marshal transition data: %v", err)
    }

    req, err := http.NewRequest("PUT", fmt.Sprintf("https://%s/api/incidents/%s/transitions", host, id), bytes.NewBuffer(jsonData))
    if err != nil {
	return fmt.Errorf("failed to create transition request: %v", err)
    }

    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
	return fmt.Errorf("failed to execute transition request: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("transition API returned status %d: %s", resp.StatusCode, string(body))
    }

    return nil
}
