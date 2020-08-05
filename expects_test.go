package rbac_test

func doctypeQuery(r string) string {
	return `
{
  "selector": {"docType": "` + r + `"},
  "limit": 10
}`
}

func expQueryOnlyCreatedBy(r string) string {
	return `
{
  "selector": {
    "$and": [
      {"docType": "` + r + `"},
      {"createdBy": "testuserID"}
    ]
  },
  "limit": 10
}`
}

const expQueryInTransfer = `
{
  "selector": {
    "$and": [
      { "docType": "transfer" },
      {
        "$or": [
          { "createdBy": "testuserID" },
          {
            "asset": {
              "$or": [{ "from": "testuserID" }, { "to": "testuserID" }]
            }
          },
          {
            "money": {
              "$or": [{ "from": "testuserID" }, { "to": "testuserID" }]
            }
          }
        ]
      }
    ]
  },
  "limit": 10
}`

func expQueryLimitFields(r string) string {
	return `
{
  "selector": {"docType": "` + r + `"},
  "limit": 10,
  "fields": [
    "createdBy",
    "created"
  ]
}`
}
