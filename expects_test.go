package rbac_test

func doctypeQuery(r string) string {
	return `
{
  "selector": {
    "docType": "` + r + `"
  },
  "limit": 10
}`
}

func expQueryOnlyCreatedBy(r string) string {
	return `
{
  "selector": {
    "docType": "` + r + `",
    "createdBy": "testuserID"
  },
  "limit": 10
}`
}

const expQueryInTransfer = `
{
  "selector": {
    "$or": [
      { "createdBy": "testuserID" },
      { "asset.from": "testuserID" },
      { "asset.to": "testuserID" },
      { "payment.from": "testuserID" },
      { "payment.to": "testuserID" }
    ],
    "docType": "transfer"
  },
  "limit": 10
}`

func expQueryLimitFields(r string) string {
	return `
{
  "selector": {
    "docType": "` + r + `"
  },
  "limit": 10,
  "fields": [
    "createdBy",
    "created"
  ]
}`
}
