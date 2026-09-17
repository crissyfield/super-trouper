package codeshare

// Project describes a project hosted on Frida CodeShare as returned by the API.
type Project struct {
	ID           string `json:"id"`               // UUID of the project.
	Name         string `json:"project_name"`     // Name of the project.
	Description  string `json:"description"`      // Description of the project.
	Owner        string `json:"owner"`            // Nickname of the project owner.
	Slug         string `json:"slug"`             // Slug of the project.
	FridaVersion string `json:"frida_version"`    // Frida version the project was published with.
	Likes        int    `json:"likes"`            // Number of likes of the project.
	Source       string `json:"source,omitempty"` // JavaScript source of the project, only present in detailed results.
}
