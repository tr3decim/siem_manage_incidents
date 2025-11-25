package main

import (
    "bytes"
    "flag"
    "encoding/json"
    "crypto/tls"
    "fmt"
    "io"
    "net/http"
    "os"
    "strings"
    "time"
)

var host string = ""
var incidentsAPIpath string = "/api/v2/incidents"
var incidentDetailsAPIpath string = "/api/incidentsReadModel/incidents/"
var updateIncidentAPIpath string = "/api/incidents/"
var updateStateIncidentAPIpath string = "/api/incidents/%s/transitions"
var viewincidentDetailsAPIpath string = "/#/incident/incidents/view/"

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

type Group struct {
    Type          string   `json:"type"`
    GroupType     string   `json:"groupType"`
    ID            string   `json:"id"`
    Name          string   `json:"name"`
    Accessibility string   `json:"accessibility"`
}

type Targets struct {
    Groups   []string      `json:"groups"`
    Assets   []string 	   `json:"assets"`
    Networks []string      `json:"networks"`
    Addresses []string     `json:"addresses"`
    Others   []string      `json:"others"`
}

type TargetsDetail struct {
    Groups   []Group      `json:"groups"`
    Assets   []Group 	   `json:"assets"`
    Networks []Group      `json:"networks"`
    Addresses []Group     `json:"addresses"`
    Others   []Group      `json:"others"`
}

type Assigned struct {
    ID		string `json:"id"`
    FirstName   string `json:"firstName"`
    LastName    string `json:"lastName"`
}

type IncidentDetail struct {
    Key         string      `json:"key"`
    Assigned    Assigned  `json:"assigned"`
    IsConfirmed bool	    `json:"isConfirmed"`
    Name        string      `json:"name"`
    Source      string      `json:"source"`
    Detected    string      `json:"detected"`
    Type        string      `json:"type"`
    Severity    string      `json:"severity"`
    Targets     TargetsDetail     `json:"targets"`
    Attackers   TargetsDetail     `json:"attackers"`
    Description string     `json:"description"`
    Groups      []Group     `json:"groups"`
    Influence   string      `json:"influence"`
    Parameters  interface{} `json:"parameters"`
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

func extractGroupIDs(groups []Group) []string {
    ids := make([]string, len(groups))
    for i, group := range groups {
		ids[i] = group.ID
    }
    return ids
}

func extractGroupOthers(groups []Group) []string {
    ids := make([]string, len(groups))
    for i, group := range groups {
		ids[i] = group.Name
    }
    return ids
}

func convertTargetsDetailToTargets(detail TargetsDetail) Targets {
    return Targets{
	    Groups:    extractGroupIDs(detail.Groups),
	    Assets:    extractGroupIDs(detail.Assets),
	    Networks:  extractGroupIDs(detail.Networks),
	    Addresses: extractGroupIDs(detail.Addresses),
	    Others:    extractGroupOthers(detail.Others),
    }
}

func getIncidentIDs(token, where string, limit int, curdate string) ([]string, error) {
    reqData := IncidentRequest{
		Offset:         0,
		Limit:          limit,
		TimeFrom:       curdate,
		FilterTimeType: "creation",
		Filter: IncidentFilter{
		    Select: []string{"key", "name", "category", "type", "status", "created", "assigned"},
		    Where:  where,
		},
    }

    jsonData, err := json.Marshal(reqData)
    if err != nil {
		return nil, fmt.Errorf("failed to marshal request data: %v", err)
    }

    req, err := http.NewRequest("POST", host + incidentsAPIpath, bytes.NewBuffer(jsonData))
    if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
    }

    req.Header.Set("Authorization", "Bearer " + token)
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

    var incidentResp IncidentResponse
    if err := json.NewDecoder(resp.Body).Decode(&incidentResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
    }

    ids := make([]string, len(incidentResp.Incidents))
    for i, incident := range incidentResp.Incidents {
		ids[i] = incident.ID
    }

    return ids, nil
}

func getIncidentDetails(token, id string) (*IncidentDetail, error) {
    req, err := http.NewRequest("GET", host + incidentDetailsAPIpath + id, nil)
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

func updateIncident(token, id string, incident *IncidentDetail, assigned string) error {
    updateData := IncidentUpdate{
	Assigned:    assigned,
	Attackers:   convertTargetsDetailToTargets(incident.Attackers),
	Description: incident.Description,
	Detected:    incident.Detected,
	Groups:      extractGroupIDs(incident.Groups),
	Influence:   incident.Influence,
	Name:        incident.Name,
	Parameters:  incident.Parameters,
	Severity:    incident.Severity,
	Source:      incident.Source,
	Targets:     convertTargetsDetailToTargets(incident.Targets),
	Type:        incident.Type,
    }

    jsonData, err := json.Marshal(updateData)
    if err != nil {
		return fmt.Errorf("failed to marshal update data: %v", err)
    }

    req, err := http.NewRequest("PUT", host + fmt.Sprintf(updateStateIncidentAPIpath, id), bytes.NewBuffer(jsonData))
    if err != nil {
		return fmt.Errorf("failed to create update request: %v", err)
    }

    req.Header.Set("Authorization", "Bearer " + token)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
		return fmt.Errorf("failed to execute update request: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update API returned status %d: %s", resp.StatusCode, string(body))
    }

    return nil
}

func performTransition(token, id, action, message string) error {
    transitionData := TransitionRequest{
	    ID:       action,
	    Measures: "",
	    Message:  message,
    }

    jsonData, err := json.Marshal(transitionData)
    if err != nil {
		return fmt.Errorf("failed to marshal transition data: %v", err)
    }

    req, err := http.NewRequest("PUT", host + updateStateIncidentAPIpath + id, bytes.NewBuffer(jsonData))
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

    if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("transition API returned status %d: %s", resp.StatusCode, string(body))
    }

    return nil
}

func processIncident(token, id, action, message, assigned string) error {
    incident, err := getIncidentDetails(token, id)
	if err != nil {
		return fmt.Errorf("failed to get incident details: %v", err)
    }

    if err := updateIncident(token, id, incident, assigned); err != nil {
		return fmt.Errorf("failed to update incident: %v", err)
    }

    if err := performTransition(token, id, action, message); err != nil {
		return fmt.Errorf("failed to perform transition: %v", err)
    }

    fmt.Printf("Processed %s - %s%s%s\n", incident.Key, host, viewincidentDetailsAPIpath, id)
    return nil
}

func processIncidents(token, where, action, message string, limit int, assigned, curdate string) error {
    ids, err := getIncidentIDs(token, where, limit, curdate)
    if err != nil {
		return fmt.Errorf("failed to get incident IDs: %v", err)
    }

    fmt.Printf("Found %d incident(s)\n", len(ids))

    for _, id := range ids {
		if err := processIncident(token, id, action, message, assigned); err != nil {
		    fmt.Printf("Failed to process incident %s: %v\n", id, err)
		    continue
		}
    }

    return nil
}

func main() {
    todo := flag.String("do", "", "What to do (\"get\" or \"update\" incident(s))")
    token := flag.String("token", "", "API token")
    corname := flag.String("corname", "*", "Correlation name or ID (key) of the incident(s) (example: Unix_Systemd_Service_Modify, INC-1313, * for all (default))")
    whereStatus := flag.String("status", "new", "Status of incidents to get (new, closed, approved)")
    action := flag.String("state", "", "Status of incident to set (Closed, Approved, InProgress or Resolved)")
    message := flag.String("msg", "", "Comment")
    limit := flag.Int("limit", 999, "Limit of incidents to get (0-999, default 999)")
    assigned := flag.String("assigned", "", "Assignee (UUID, example: 107dd2cd-4ac2-4af5-8c3e-9feec2fcd74c)")
    curdate := flag.String("date", "", "From when search incidents (example: 2025-13-13T13:13:13.131Z)")
    hostname := flag.String("host", "", "SIEM hostname")

    flag.Parse()

    if *todo == "" || *token == "" || *corname == "" || *hostname == "" {
        fmt.Println("Error: Missing required arguments")
        flag.Usage()
        os.Exit(1)
    }

    if strings.Contains(*token, " ") || strings.Contains(*corname, " ") || strings.Contains(*hostname, " ") {
        fmt.Println("Error: No space available in token, correlation name and hostname")
        os.Exit(1)
    }

    host = fmt.Sprintf("https://%s", *hostname)

    if *curdate == "" {
		*curdate = time.Now().UTC().Truncate(24 * time.Hour).Format("2006-01-02T15:04:05.000Z")
    }

    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

    where := ""

    if strings.Contains(*corname, ",") {
		whereConditions := strings.Split(*corname, ",")
	
		for _, whereCondition := range whereConditions {
		    if where != "" {
		    where += " OR "
		    }
	
		    if strings.Contains(whereCondition, "INC") {
		    where += fmt.Sprintf("key = '%s'", whereCondition)
		    } else {
		    where += fmt.Sprintf("CorrelationNames = '%s'", whereCondition)
		    }
		}
	
		where += fmt.Sprintf(" AND status = '%s'", *whereStatus)
    } else if *corname != "*" {
		if strings.Contains(*corname, "INC") {
		    where += fmt.Sprintf("key = '%s'", *corname)
		} else {
		    where += fmt.Sprintf("CorrelationNames = '%s'", *corname)
		}
    } else {
		where = fmt.Sprintf("status = '%s'", *whereStatus)
    }

    switch *todo {
    case "get":
        ids, err := getIncidentIDs(*token, where, *limit, *curdate)
        if err != nil {
            fmt.Printf("Error: %v\n", err)
            os.Exit(1)
        }

    fromDate, err := time.Parse(time.RFC3339Nano, *curdate)
    if err != nil {
        fmt.Println("Error in parsing timestamp: %v\n", err)
    }

    fmt.Printf("Found %v incident(s) from %v\n", len(ids), fromDate.Format("January 02, 2006 at 15:04:05"))

        for _, id := range ids {
            incident, err := getIncidentDetails(*token, id)
            if err != nil {
                fmt.Printf("failed to get incident details: %v", err)
            } else {
				detected, err := time.Parse(time.RFC3339Nano, incident.Detected)
				if err != nil {
				    fmt.Printf("Error in parsing timestamp: %v\n", err)
				}
				timedate := detected.Format("January 02, 2006 at 15:04:05")
		
				fmt.Printf("# %s\n- Detected at: %s (%s)\n- Description: %s\n- Type: %s\n- Severity: %s\n- Assigned: %s %s\n- Confirmed: %v\n\n", 
				    incident.Key, timedate, incident.Detected, incident.Description, 
				    incident.Type, incident.Severity, incident.Assigned.FirstName, 
				    incident.Assigned.LastName, incident.IsConfirmed)
            }
        }
    case "update":
        validActions := map[string]bool{
            "Closed":     true,
            "Approved":   true,
            "InProgress": true,
            "Resolved":   true,
        }
        if !validActions[*action] {
            fmt.Println("Error: Incorrect action. Must be one of: Closed, Approved, InProgress, Resolved")
            os.Exit(1)
        }

        if *message == "" {
            fmt.Println("Error: Message is required for update mode")
            os.Exit(1)
        }

        if err := processIncidents(*token, where, *action, *message, *limit, *assigned, *curdate); err != nil {
            fmt.Printf("Error: %v\n", err)
            os.Exit(1)
        }
    default:
        flag.Usage()
        return
    }
}

func init() {
    flag.Usage = func() {
        path, _ := os.Executable()
        name := strings.Split(path, "/")
        exeName := name[len(name)-1]

        fmt.Printf("Usage of %s:\n", exeName)
        fmt.Println("Flags:")
        flag.PrintDefaults()
        fmt.Println("\nExamples:")
        fmt.Printf("  %s --do get --token \"your-token\" --corname \"Unix_Systemd_Service_Modify\" --limit 10\n", exeName)
        fmt.Printf("  %s --do update --token \"your-token\" --corname \"Unix_Systemd_Service_Modify\" --action Closed --msg \"Resolved\" --assigned \"107dd2cd-4ac2-4af5-8c3e-9feec2fcd74c\"\n", exeName)
    }
}
