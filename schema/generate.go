package schema

//go:generate go get -d -v github.com/atombender/go-jsonschema/cmd/gojsonschema@v0.9.1-0.20211117143334-fdc071e07e6c
//go:generate go run github.com/atombender/go-jsonschema/cmd/gojsonschema --schema-package=https://id.uvci.eu/DCC.combined-schema.json=github.com/icedream/fancy-vaccert/schema --schema-output https://id.uvci.eu/DCC.combined-schema.json=dcc.go --schema-package=https://id.uvci.eu/DCC.schema.json=github.com/icedream/fancy-vaccert/schema --schema-output=https://id.uvci.eu/DCC.schema.json=dcc.go --schema-package=https://id.uvci.eu/DCC.Core.Types.schema.json=github.com/icedream/fancy-vaccert/schema --schema-output=https://id.uvci.eu/DCC.Core.Types.schema.json=dcc_core_types.go --schema-package=https://id.uvci.eu/DCC.Types.schema.json=github.com/icedream/fancy-vaccert/schema --schema-output=https://id.uvci.eu/DCC.Types.schema.json=dcc_types.go --schema-package=https://id.uvci.eu/DCC.ValueSets.schema.json=github.com/icedream/fancy-vaccert/schema --schema-output=https://id.uvci.eu/DCC.ValueSets.schema.json=dcc_value_sets.go ./enh-dcc-schema/DCC.combined-schema.json --verbose
