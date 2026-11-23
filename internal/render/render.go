// Package render выводит снимок статистики в терминал.
package render

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"netwatch/internal/models"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// Renderer печатает снимки статистики.
type Renderer struct {
	out   io.Writer
	color bool
}

// New создаёт рендер. noClear отключает очистку экрана и цвета (для pipe/логов).
func New(out io.Writer, noClear bool) *Renderer {
	return &Renderer{out: out, color: !noClear}
}

func (r *Renderer) paint(code, s string) string {
	if !r.color {
		return s
	}
	return code + s + ansiReset
}

// Draw печатает полный кадр статистики.
func (r *Renderer) Draw(s models.Snapshot) {
	var b strings.Builder
	if r.color {
		b.WriteString("\033[H\033[2J")
	}
	r.writeHeader(&b, s)
	r.writeAlerts(&b, s)
	headers, rows := flowsTable(s.TopFlows)
	r.writeSection(&b, "ТОП ПОТОКОВ", headers, rows)
	headers, rows = hostsTable(s.TopHosts)
	r.writeSection(&b, "ТОП ХОСТОВ", headers, rows)
	headers, rows = countsTable(s.TopDomains, false)
	r.writeSection(&b, "ТОП ДОМЕНОВ", headers, rows)
	headers, rows = countsTable(s.Protocols, true)
	r.writeSection(&b, "ПРОТОКОЛЫ", headers, rows)
	headers, rows = countsTable(s.Apps, true)
	r.writeSection(&b, "СЕРВИСЫ", headers, rows)
	fmt.Fprint(r.out, b.String())
}

func (r *Renderer) writeHeader(b *strings.Builder, s models.Snapshot) {
	fmt.Fprintf(b, "%s  %s %s   аптайм %s   потоков: %d\n",
		r.paint(ansiBold, "netwatch"),
		r.paint(ansiDim, "•"),
		s.Source, s.Uptime, s.FlowsTotal)
	fmt.Fprintf(b, "%s всего: %s / %s пакетов   %s скорость: %s/с, %.0f пакетов/с\n\n",
		r.paint(ansiDim, "•"),
		humanBytes(s.TotalBytes), humanCount(s.TotalPackets),
		r.paint(ansiDim, "•"),
		humanBytes(uint64(s.RateBPS)), s.RatePPS)
}

func (r *Renderer) writeAlerts(b *strings.Builder, s models.Snapshot) {
	if len(s.Alerts) == 0 {
		return
	}
	fmt.Fprintf(b, "%s\n", r.paint(ansiBold, "СОБЫТИЯ"))
	for i, a := range s.Alerts {
		if i >= 5 {
			break
		}
		code := ansiYellow
		switch a.Severity {
		case "crit":
			code = ansiRed
		case "info":
			code = ansiCyan
		}
		fmt.Fprintf(b, "  %s %s — %s\n",
			r.paint(code, "["+a.Kind+"]"), a.Time.Format("15:04:05"), a.Message)
	}
	b.WriteString("\n")
}

func (r *Renderer) writeSection(b *strings.Builder, title string, headers []string, rows [][]string) {
	fmt.Fprintf(b, "%s\n", r.paint(ansiBold, title))
	tw := tabwriter.NewWriter(b, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	_ = tw.Flush()
	b.WriteString("\n")
}

func flowsTable(flows []models.FlowView) ([]string, [][]string) {
	headers := []string{"ИСТОЧНИК", "НАЗНАЧЕНИЕ", "ПРОТОКОЛ", "СЕРВИС", "БАЙТЫ", "ПАКЕТЫ", "АКТИВЕН"}
	rows := make([][]string, 0, len(flows))
	for _, f := range flows {
		app := "—"
		if len(f.Apps) > 0 {
			app = f.Apps[0].Name
		}
		rows = append(rows, []string{
			f.Key.A.String(),
			f.Key.B.String(),
			f.Key.Proto,
			app,
			humanBytes(f.Bytes),
			humanCount(f.Packets),
			ago(f.LastSeen),
		})
	}
	return headers, rows
}

func hostsTable(hosts []models.HostView) ([]string, [][]string) {
	headers := []string{"ХОСТ", "ИМЯ (DNS)", "ВХОДЯЩИЙ", "ИСХОДЯЩИЙ", "ПАКЕТЫ"}
	rows := make([][]string, 0, len(hosts))
	for _, h := range hosts {
		name := h.Name
		if name == "" {
			name = "—"
		}
		rows = append(rows, []string{
			h.IP.String(),
			name,
			humanBytes(h.InBytes),
			humanBytes(h.OutBytes),
			humanCount(h.Packets),
		})
	}
	return headers, rows
}

func countsTable(counts []models.Count, inBytes bool) ([]string, [][]string) {
	headers := []string{"ИМЯ", "ЗНАЧЕНИЕ", "ДОЛЯ", ""}
	rows := make([][]string, 0, len(counts))

	var total uint64
	for _, c := range counts {
		total += c.Value
	}
	for _, c := range counts {
		value := humanCount(c.Value)
		if inBytes {
			value = humanBytes(c.Value)
		}
		share := 0.0
		if total > 0 {
			share = float64(c.Value) / float64(total) * 100
		}
		width := 0
		if total > 0 {
			width = int(float64(c.Value) / float64(total) * 20)
		}
		rows = append(rows, []string{
			c.Name,
			value,
			fmt.Sprintf("%.1f%%", share),
			strings.Repeat("█", width),
		})
	}
	return headers, rows
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	return d.Round(time.Second).String()
}

func humanBytes(v uint64) string {
	if v < 1024 {
		return fmt.Sprintf("%d Б", v)
	}
	units := []string{"КБ", "МБ", "ГБ", "ТБ"}
	f := float64(v)
	i := -1
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

func humanCount(v uint64) string {
	if v < 1000 {
		return strconv.FormatUint(v, 10)
	}
	units := []string{"тыс.", "млн", "млрд"}
	f := float64(v)
	i := -1
	for f >= 1000 && i < len(units)-1 {
		f /= 1000
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}
