// dbquery 蜜罐数据库查询工具：打印各表内容，用于运营核查。
// 用法: go run ./cmd/dbquery [-db data/honeypot.db]
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

func main() {
	dbPath := flag.String("db", "data/honeypot.db", "sqlite db path")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(1)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, opened_at, source_ip, source_port, target_port, client_version, closed_at FROM connections")
	if err != nil {
		fmt.Fprintln(os.Stderr, "query connections:", err)
		os.Exit(1)
	}
	fmt.Println("== connections ==")
	for rows.Next() {
		var id, opened, ip, cver, closed sql.NullString
		var sport, tport sql.NullInt64
		if err := rows.Scan(&id, &opened, &ip, &sport, &tport, &cver, &closed); err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			os.Exit(1)
		}
		fmt.Printf("  %s | %s | %s:%d -> :%d | client=%s | closed=%s\n",
			id.String, opened.String, ip.String, sport.Int64, tport.Int64, cver.String, closed.String)
	}
	rows.Close()

	rows, err = db.Query("SELECT connection_id, ts, username, password, method, success, delay_ms FROM auth_attempts")
	if err != nil {
		fmt.Fprintln(os.Stderr, "query auth_attempts:", err)
		os.Exit(1)
	}
	fmt.Println("== auth_attempts ==")
	for rows.Next() {
		var conn, ts, user, pass, method sql.NullString
		var success, delay sql.NullInt64
		if err := rows.Scan(&conn, &ts, &user, &pass, &method, &success, &delay); err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			os.Exit(1)
		}
		fmt.Printf("  %s | %s | user=%s pass=%s method=%s success=%d delay=%dms\n",
			conn.String, ts.String, user.String, pass.String, method.String, success.Int64, delay.Int64)
	}
	rows.Close()

	rows, err = db.Query("SELECT id, connection_id, channel_type, term, opened_at, closed_at FROM sessions")
	if err != nil {
		fmt.Fprintln(os.Stderr, "query sessions:", err)
		os.Exit(1)
	}
	fmt.Println("== sessions ==")
	for rows.Next() {
		var sid, conn, ctype, term, opened, closed sql.NullString
		if err := rows.Scan(&sid, &conn, &ctype, &term, &opened, &closed); err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			os.Exit(1)
		}
		fmt.Printf("  %s | conn=%s | type=%s term=%s | %s -> %s\n",
			sid.String, conn.String, ctype.String, term.String, opened.String, closed.String)
	}
	rows.Close()

	rows, err = db.Query("SELECT session_id, ts, command, cwd, exit_code, duration_ms, output_preview FROM commands")
	if err != nil {
		fmt.Fprintln(os.Stderr, "query commands:", err)
		os.Exit(1)
	}
	fmt.Println("== commands ==")
	for rows.Next() {
		var sid, ts, cmd, cwd, preview sql.NullString
		var code, dur sql.NullInt64
		if err := rows.Scan(&sid, &ts, &cmd, &cwd, &code, &dur, &preview); err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			os.Exit(1)
		}
		fmt.Printf("  %s | %s | cwd=%s | code=%d dur=%dms | %s\n  command: %s\n  preview: %s\n",
			sid.String, ts.String, cwd.String, code.Int64, dur.Int64, preview.String, cmd.String, preview.String)
	}
	rows.Close()
}
