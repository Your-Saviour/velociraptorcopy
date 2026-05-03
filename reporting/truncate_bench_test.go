package reporting

import (
	"strings"
	"testing"

	"github.com/Depado/bfchroma"
	chroma_html "github.com/alecthomas/chroma/formatters/html"
	blackfriday "github.com/russross/blackfriday/v2"
)

// realVQLLines contains representative VQL lines at varying lengths.
// Short lines are simple queries; longer lines reflect real artifacts that
// embed PowerShell/Bash snippets, long format strings, or chained globs —
// the main real-world source of >200 char lines. Each line has a realistic
// mix of keywords, quoted strings (single and triple), operators, and
// identifiers, producing the same HTML-entity distribution as production VQL.
var realVQLLines = []string{
	// ~50 chars — typical short query lines
	`SELECT * FROM info()`,
	`LET X = SELECT Name, Pid FROM pslist()`,
	`SELECT FullPath FROM glob(globs='C:/Windows/*.exe')`,

	// ~150 chars — medium lines with function calls and operators
	`LET FileList = SELECT FullPath, Name, Size, Mtime FROM glob(globs=format(format='%v/**/*.exe', args=[RootDir]), accessor='file')`,
	`SELECT Name, CommandLine, Pid, Ppid FROM pslist() WHERE Name =~ 'powershell' OR Name =~ 'cmd.exe'`,

	// ~300–500 chars — long lines typical of artifacts embedding shell one-liners
	`LET PSCmd = SELECT * FROM execve(argv=['powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-Command', format(format='''Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648; StartTime=(Get-Date).AddDays(-7)} | Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 3''', args=[])])`,
	`LET Results = SELECT * FROM foreach(row={SELECT FullPath FROM glob(globs='C:/Users/*/AppData/Roaming/*.exe')}, query={SELECT FullPath, hash(path=FullPath, hashselect='MD5,SHA256') AS Hashes, authenticode(filename=FullPath) AS Sig FROM scope() WHERE NOT Sig.Trusted})`,

	// ~800–1000 chars — very long lines with embedded multi-line scripts
	`LET Script = '''$ErrorActionPreference = 'SilentlyContinue'; $Results = @(); Get-ChildItem -Path 'C:\Users' -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.exe','.dll','.ps1','.bat' -and $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | ForEach-Object { $Hash = (Get-FileHash -Path $_.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash; $Results += [PSCustomObject]@{Path=$_.FullName; Hash=$Hash; Size=$_.Length; Modified=$_.LastWriteTime} }; $Results | ConvertTo-Json -Depth 2'''`,

	// ~1500–2000 chars — extreme lines with base64 payloads or very long regex patterns
	`LET YaraRule = '''rule SuspiciousPE { meta: description = "Detects suspicious PE with packed or encrypted sections" author = "Velociraptor" strings: $mz = { 4D 5A } $upx0 = "UPX0" ascii $upx1 = "UPX1" ascii $upx2 = "UPX2" ascii $packed = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 2C E8 } $entropy_check = { E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? 8B 45 FC 05 ?? ?? ?? ?? 50 } condition: uint16(0) == 0x5A4D and filesize < 10MB and ($mz at 0) and (($upx0 and $upx1) or ($upx2) or ($packed) or (2 of ($upx0,$upx1,$entropy_check))) and not filepath matches /Windows\\System32/ }'''`,
}

// benchVQL builds a markdown VQL code block repeating lines from realVQLLines
// until the total byte count of each line approximates targetLineLen.
// It pads short lines with a trailing format() call to reach the target length.
func benchVQL(targetLineLen int) []byte {
	var sb strings.Builder
	sb.WriteString("```vql\n")
	for i := 0; i < 20; i++ {
		base := realVQLLines[i%len(realVQLLines)]
		line := base
		// Pad short lines up to the target length.
		for len(line) < targetLineLen-40 {
			line += format(" AND FullPath =~ 'C:/Users/%v/AppData'", i)
		}
		// Clamp lines that are already longer than the target.
		if len(line) > targetLineLen {
			line = line[:targetLineLen]
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	sb.WriteString("```\n")
	return []byte(sb.String())
}

func format(f string, args ...interface{}) string {
	return strings.NewReplacer("%v", strings.Repeat("x", 8)).Replace(f)
}

func chromaRender(md []byte) string {
	output := blackfriday.Run(
		md,
		blackfriday.WithRenderer(bfchroma.NewRenderer(
			bfchroma.ChromaOptions(
				chroma_html.ClassPrefix("chroma"),
				chroma_html.WithClasses(true),
				chroma_html.WithLineNumbers(true)),
			bfchroma.Style("github"),
		)))
	return string(output)
}

func BenchmarkTruncateChromaLines_20x50(b *testing.B) {
	html := chromaRender(benchVQL(50))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		truncateChromaLines(html, 200)
	}
}

func BenchmarkTruncateChromaLines_20x500(b *testing.B) {
	html := chromaRender(benchVQL(500))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		truncateChromaLines(html, 200)
	}
}

func BenchmarkTruncateChromaLines_20x1000(b *testing.B) {
	html := chromaRender(benchVQL(1000))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		truncateChromaLines(html, 200)
	}
}

func BenchmarkTruncateChromaLines_20x2000(b *testing.B) {
	html := chromaRender(benchVQL(2000))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		truncateChromaLines(html, 200)
	}
}

// BenchmarkRender_* — full chroma render on raw (un-pre-truncated) VQL.
// These represent the worst-case cost before smart pre-truncation kicks in.

func BenchmarkRender_20x50(b *testing.B) {
	md := benchVQL(50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = chromaRender(md)
	}
}

func BenchmarkRender_20x500(b *testing.B) {
	md := benchVQL(500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = chromaRender(md)
	}
}

func BenchmarkRender_20x1000(b *testing.B) {
	md := benchVQL(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = chromaRender(md)
	}
}

func BenchmarkRender_20x2000(b *testing.B) {
	md := benchVQL(2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = chromaRender(md)
	}
}

// naiveTruncateLine is the original pre-smart-truncate implementation:
// a plain byte-slice cut with no string-state awareness.
func naiveTruncateLine(line string, cutLen int) string {
	if len(line) <= cutLen {
		return line
	}
	return line[:cutLen] + " ..."
}

// BenchmarkNaiveTruncate_* — cost of the original naive truncation for comparison.

func BenchmarkNaiveTruncate_20x50(b *testing.B) {
	lines := strings.Split(string(benchVQL(50)), "\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range lines {
			_ = naiveTruncateLine(l, 200)
		}
	}
}

func BenchmarkNaiveTruncate_20x500(b *testing.B) {
	lines := strings.Split(string(benchVQL(500)), "\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range lines {
			_ = naiveTruncateLine(l, 200)
		}
	}
}

func BenchmarkNaiveTruncate_20x1000(b *testing.B) {
	lines := strings.Split(string(benchVQL(1000)), "\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range lines {
			_ = naiveTruncateLine(l, 200)
		}
	}
}

func BenchmarkNaiveTruncate_20x2000(b *testing.B) {
	lines := strings.Split(string(benchVQL(2000)), "\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range lines {
			_ = naiveTruncateLine(l, 200)
		}
	}
}

// BenchmarkSmartTruncate_* — cost of smartTruncateLine on 20 lines (raw VQL,
// before chroma). This is the new pre-truncation overhead in report.go.

func BenchmarkSmartTruncate_20x50(b *testing.B) {
	lines := strings.Split(string(benchVQL(50)), "\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range lines {
			_ = smartTruncateLine(l, 200)
		}
	}
}

func BenchmarkSmartTruncate_20x500(b *testing.B) {
	lines := strings.Split(string(benchVQL(500)), "\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range lines {
			_ = smartTruncateLine(l, 200)
		}
	}
}

func BenchmarkSmartTruncate_20x1000(b *testing.B) {
	lines := strings.Split(string(benchVQL(1000)), "\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range lines {
			_ = smartTruncateLine(l, 200)
		}
	}
}

func BenchmarkSmartTruncate_20x2000(b *testing.B) {
	lines := strings.Split(string(benchVQL(2000)), "\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range lines {
			_ = smartTruncateLine(l, 200)
		}
	}
}

// BenchmarkNaiveFullPipeline_* — original naive truncation + chroma render, no HTML truncation.

func BenchmarkNaiveFullPipeline_20x50(b *testing.B) {
	raw := benchVQL(50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lines := strings.Split(string(raw), "\n")
		for j, l := range lines {
			lines[j] = naiveTruncateLine(l, 200)
		}
		_ = chromaRender([]byte("```vql\n" + strings.Join(lines, "\n") + "\n```\n"))
	}
}

func BenchmarkNaiveFullPipeline_20x500(b *testing.B) {
	raw := benchVQL(500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lines := strings.Split(string(raw), "\n")
		for j, l := range lines {
			lines[j] = naiveTruncateLine(l, 200)
		}
		_ = chromaRender([]byte("```vql\n" + strings.Join(lines, "\n") + "\n```\n"))
	}
}

func BenchmarkNaiveFullPipeline_20x1000(b *testing.B) {
	raw := benchVQL(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lines := strings.Split(string(raw), "\n")
		for j, l := range lines {
			lines[j] = naiveTruncateLine(l, 200)
		}
		_ = chromaRender([]byte("```vql\n" + strings.Join(lines, "\n") + "\n```\n"))
	}
}

func BenchmarkNaiveFullPipeline_20x2000(b *testing.B) {
	raw := benchVQL(2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lines := strings.Split(string(raw), "\n")
		for j, l := range lines {
			lines[j] = naiveTruncateLine(l, 200)
		}
		_ = chromaRender([]byte("```vql\n" + strings.Join(lines, "\n") + "\n```\n"))
	}
}

// BenchmarkFullPipeline_* — smart pre-truncation + chroma render + HTML truncation.
// This is the actual end-to-end cost of the new pipeline.

func BenchmarkFullPipeline_20x50(b *testing.B) {
	raw := benchVQL(50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		preTruncated := truncateLongLines(string(raw))
		html := chromaRender([]byte("```vql\n" + preTruncated + "\n```\n"))
		_ = truncateChromaLines(html, 200)
	}
}

func BenchmarkFullPipeline_20x500(b *testing.B) {
	raw := benchVQL(500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		preTruncated := truncateLongLines(string(raw))
		html := chromaRender([]byte("```vql\n" + preTruncated + "\n```\n"))
		_ = truncateChromaLines(html, 200)
	}
}

func BenchmarkFullPipeline_20x1000(b *testing.B) {
	raw := benchVQL(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		preTruncated := truncateLongLines(string(raw))
		html := chromaRender([]byte("```vql\n" + preTruncated + "\n```\n"))
		_ = truncateChromaLines(html, 200)
	}
}

func BenchmarkFullPipeline_20x2000(b *testing.B) {
	raw := benchVQL(2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		preTruncated := truncateLongLines(string(raw))
		html := chromaRender([]byte("```vql\n" + preTruncated + "\n```\n"))
		_ = truncateChromaLines(html, 200)
	}
}
