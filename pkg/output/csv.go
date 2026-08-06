package output

import (
	"encoding/csv"
	"io"
)

func RenderCSV(w io.Writer, headers []string, rows [][]string) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return writer.Error()
}
