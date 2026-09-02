// S3 XML wire types. Element names match the S3 API specification exactly;
// they are the contract with every S3 client, so renaming a field here changes
// the wire format.
//
// Optional elements are pointers so that "absent" and "present but empty" stay
// distinguishable — S3 clients treat a missing NextContinuationToken very
// differently from an empty one.

package s3

import (
	"encoding/xml"
)

// xmlns is the S3 API namespace every response carries.
const xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"

// xmlProlog precedes every rendered document.
const xmlProlog = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

// render marshals v with the XML prolog. A marshalling failure would mean a
// malformed wire type, which is a programming error rather than a request
// error, so it surfaces as an empty body and a logged 500 upstream.
func render(v any) ([]byte, error) {
	body, err := xml.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append([]byte(xmlProlog), body...), nil
}

// ---- ListBuckets ----

type listAllMyBucketsResult struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Xmlns   string   `xml:"xmlns,attr"`
	Owner   owner    `xml:"Owner"`
	Buckets buckets  `xml:"Buckets"`
}

type owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type buckets struct {
	Bucket []bucketEntry `xml:"Bucket"`
}

type bucketEntry struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

// ---- GetBucketLocation / GetBucketVersioning ----

type locationConstraint struct {
	XMLName xml.Name `xml:"LocationConstraint"`
	Xmlns   string   `xml:"xmlns,attr"`
	Region  string   `xml:",chardata"`
}

// versioningConfiguration is deliberately empty: versioning is unsupported, and
// an empty configuration is how S3 reports "never enabled".
type versioningConfiguration struct {
	XMLName xml.Name `xml:"VersioningConfiguration"`
	Xmlns   string   `xml:"xmlns,attr"`
}

// ---- ListObjects (V1 and V2 share this shape) ----

type listBucketResult struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	Xmlns       string   `xml:"xmlns,attr"`
	Name        string   `xml:"Name"`
	Prefix      string   `xml:"Prefix"`
	Delimiter   *string  `xml:"Delimiter,omitempty"`
	MaxKeys     int      `xml:"MaxKeys"`
	KeyCount    int      `xml:"KeyCount"`
	IsTruncated bool     `xml:"IsTruncated"`
	// V2 pagination.
	ContinuationToken     *string `xml:"ContinuationToken,omitempty"`
	NextContinuationToken *string `xml:"NextContinuationToken,omitempty"`
	// V1 pagination.
	Marker     *string `xml:"Marker,omitempty"`
	NextMarker *string `xml:"NextMarker,omitempty"`

	Contents       []contents     `xml:"Contents"`
	CommonPrefixes []commonPrefix `xml:"CommonPrefixes"`
}

type contents struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type commonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// ---- CopyObject ----

type copyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	Xmlns        string   `xml:"xmlns,attr"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

// ---- Multipart ----

type initiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

type completeMultipartUploadResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

type listPartsResult struct {
	XMLName              xml.Name    `xml:"ListPartsResult"`
	Xmlns                string      `xml:"xmlns,attr"`
	Bucket               string      `xml:"Bucket"`
	Key                  string      `xml:"Key"`
	UploadID             string      `xml:"UploadId"`
	PartNumberMarker     int32       `xml:"PartNumberMarker"`
	NextPartNumberMarker *int32      `xml:"NextPartNumberMarker,omitempty"`
	MaxParts             int64       `xml:"MaxParts"`
	IsTruncated          bool        `xml:"IsTruncated"`
	Parts                []partEntry `xml:"Part"`
}

type partEntry struct {
	PartNumber int32  `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
	Size       int64  `xml:"Size"`
}

type listMultipartUploadsResult struct {
	XMLName     xml.Name      `xml:"ListMultipartUploadsResult"`
	Xmlns       string        `xml:"xmlns,attr"`
	Bucket      string        `xml:"Bucket"`
	Prefix      string        `xml:"Prefix"`
	MaxUploads  int64         `xml:"MaxUploads"`
	IsTruncated bool          `xml:"IsTruncated"`
	Uploads     []uploadEntry `xml:"Upload"`
}

type uploadEntry struct {
	Key       string `xml:"Key"`
	UploadID  string `xml:"UploadId"`
	Initiated string `xml:"Initiated"`
}

// completeMultipartUpload is the client's manifest of parts to assemble.
type completeMultipartUpload struct {
	XMLName xml.Name       `xml:"CompleteMultipartUpload"`
	Parts   []completePart `xml:"Part"`
}

type completePart struct {
	PartNumber int32 `xml:"PartNumber"`
	// ETag is optional; when present it is checked against the staged part.
	ETag *string `xml:"ETag"`
}

// ---- DeleteObjects ----

// deleteRequest is the body of a batch delete (POST /{namespace}?delete).
type deleteRequest struct {
	XMLName xml.Name            `xml:"Delete"`
	Objects []deleteObjectEntry `xml:"Object"`
	// Quiet suppresses the per-key Deleted entries in the response.
	Quiet bool `xml:"Quiet"`
}

type deleteObjectEntry struct {
	Key string `xml:"Key"`
}

type deleteResult struct {
	XMLName xml.Name           `xml:"DeleteResult"`
	Xmlns   string             `xml:"xmlns,attr"`
	Deleted []deletedEntry     `xml:"Deleted"`
	Errors  []deleteErrorEntry `xml:"Error"`
}

type deletedEntry struct {
	Key string `xml:"Key"`
}

type deleteErrorEntry struct {
	Key     string `xml:"Key"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}
