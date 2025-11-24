# Author_Name-Shankar_Raghupathi
# Version-1.2
# This_Script_will_preserve_necessary_data_as_a_final_report_by_cleaning_up_the_raw_Qualys-csv_file.
# check_python_availablity & Run:- pip install pandas openpyxl
 
import pandas as pd
import glob
import os
from openpyxl import load_workbook
from openpyxl.styles import PatternFill, Font
import re
from datetime import datetime
 
# Get all CSV files in the current directory
csv_files = glob.glob("*.csv")
 
for csv_file in csv_files:
    print(f"Processing {csv_file}...")
 
    try:
        # Read the CSV
        df = pd.read_csv(csv_file)
 
        # --- Deduplicate by IP + Title ---
        if "Title" in df.columns and "IP" in df.columns:
            df = df.drop_duplicates(subset=["IP", "Title"])
 
        # --- Transformations ---
        df['IP Status'] = df['IP Status'].astype(str).str.lower()
 
        scanned_ips = (
            df[df['IP Status'].str.contains("host scanned")]['IP']
            .dropna()
            .unique()
            .tolist()
        )
 
        not_scanned_ips = (
            df[df['IP Status'].str.contains("hosts not scanned")]['IP']
            .dropna()
            .unique()
            .tolist()
        )
 
        if "Type" in df.columns:
            df = df[df["Type"].astype(str).str.lower() == "vuln"]
 
        df["Severity"] = pd.to_numeric(df["Severity"], errors="coerce")
        df = df[df["Severity"].isin([2, 3, 4, 5])]
 
        severity_map = {5: "Critical", 4: "High", 3: "Medium", 2: "Low"}
        df["SeverityLabel"] = df["Severity"].map(severity_map)
 
        severity_rank = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
        df["SeverityRank"] = df["SeverityLabel"].map(severity_rank)
        df = df.drop_duplicates(subset=["IP", "QID"], keep="last")
 
        drop_cols = ['FQDN', 'CVSS Temporal', 'CVSS3.1 Base', 'CVSS3.1 Temporal',
                     'Instance', 'QID', 'Vendor Reference', 'Bugtraq ID']
        df.drop(
            columns=[
                c for c in drop_cols if c in df.columns],
            inplace=True)
 
        df = df.sort_values(by="SeverityRank")
 
        va_df = df[(df["IP"].notnull()) & (
            df["Exploitability"].isnull())].copy()
        si_df = df[(df["IP"].notnull()) & (
            df["Exploitability"].notnull())].copy()
 
        va_df["Severity"] = va_df["SeverityLabel"]
        si_df["Severity"] = si_df["SeverityLabel"]
        va_df.drop(columns=["SeverityLabel", "SeverityRank"], inplace=True)
        si_df.drop(columns=["SeverityLabel", "SeverityRank"], inplace=True)
 
        # --- Expand Not Scanned IPs ---
        def expand_ip_range(ip_range):
            if "-" not in ip_range:
                return [ip_range.strip()]
            start_ip, end_ip = ip_range.split("-")
            start_parts = list(map(int, start_ip.split(".")))
            end_parts = list(map(int, end_ip.split(".")))
 
            # assume only last octet ranges
            ips = []
            for last in range(start_parts[3], end_parts[3] + 1):
                ips.append(
                    f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{last}")
            return ips
 
        expanded_not_scanned = []
        for item in not_scanned_ips:
            for part in str(item).split(","):
                expanded_not_scanned.extend(expand_ip_range(part.strip()))
 
        scope_df = pd.DataFrame({
            "Scanned IPs": pd.Series(scanned_ips),
            "Not Scanned IPs": pd.Series(expanded_not_scanned)
        })
 
        summary_df = pd.DataFrame({
            "Category": ["Scanned IPs", "Not Scanned IPs", "Total IPs"],
            "Count": [len(scanned_ips), len(expanded_not_scanned),
                      len(set(scanned_ips + expanded_not_scanned))]
        })
 
        va_counts = va_df["Severity"].value_counts().reindex(
            ["Critical", "High", "Medium", "Low"]).fillna(0).astype(int)
        si_counts = si_df["Severity"].value_counts().reindex(
            ["Critical", "High", "Medium", "Low"]).fillna(0).astype(int)
 
        total_va = len(va_df)
        total_si = len(si_df)
        total_all = total_va + total_si
 
        dashboard_df = pd.DataFrame({
    "Category": [
        "Vulnerability Assessment - Critical",
        "Vulnerability Assessment - High",
        "Vulnerability Assessment - Medium",
        "Vulnerability Assessment - Low",
         "",  # Spacer row
        "Security Issues - Critical",
        "Security Issues - High",
        "Security Issues - Medium",
        "Security Issues - Low",
        "Total Vulnerabilities"
    ],
    "Count": [
        va_counts["Critical"],
        va_counts["High"],
        va_counts["Medium"],
        va_counts["Low"],
        None,  # Spacer value 
        si_counts["Critical"],
        si_counts["High"],
        si_counts["Medium"],
        si_counts["Low"],
        total_all
    ]
})
 
        # --- Owner column check ---
        owner_df = None
        asset_file = "Asset-list.xlsx"   # ensure correct filename
        if os.path.exists(asset_file):
            asset_df = pd.read_excel(asset_file)
            asset_df.columns = asset_df.columns.str.strip().str.lower()
 
            if "ip" in asset_df.columns and "owner" in asset_df.columns:
                asset_map = dict(zip(asset_df["ip"], asset_df["owner"]))
 
                def get_owner(ip):
                    return asset_map.get(ip, "Name Not Available")
 
                va_df["Owner"] = va_df["IP"].map(get_owner)
                si_df["Owner"] = si_df["IP"].map(get_owner)
 
                # Build Owner tab
                owner_df = pd.DataFrame({
                    "IP": pd.concat([va_df["IP"], si_df["IP"]]).unique()
                })
                owner_df["Owner"] = owner_df["IP"].map(get_owner)
 
        # Build output filename
        base_name = os.path.splitext(csv_file)[0]
        output_file = f"{base_name}_final.xlsx"
 
        # Remove old file if exists
        if os.path.exists(output_file):
            try:
                os.remove(output_file)
            except PermissionError:
                print(f"⚠️ Skipping {csv_file}: {output_file} is open/locked.")
                continue
 
        # Write Excel
        with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
            dashboard_df.to_excel(writer, sheet_name="Dashboard", index=False)
            va_df.to_excel(
                writer,
                sheet_name="Vulnerability Assessment",
                index=False)
            si_df.to_excel(writer, sheet_name="Security Issues", index=False)
            scope_df.to_excel(
                writer,
                sheet_name="Scope",
                index=False,
                startrow=0)
            summary_df.to_excel(writer, sheet_name="Scope", index=False,
                                startrow=len(scope_df) + 3)
            if owner_df is not None:
                owner_df.to_excel(writer, sheet_name="Owner", index=False)
 
        # Apply formatting
        wb = load_workbook(output_file)
 
        ws = wb["Dashboard"]
        for cell in ws[1]:
            cell.font = Font(bold=True)
 
        dashboard_fills = {
            "critical": PatternFill(start_color="FF800000", end_color="FF800000", fill_type="solid"),
            "high": PatternFill(start_color="FFFF0000", end_color="FFFF0000", fill_type="solid"),
            "medium": PatternFill(start_color="FFFFA500", end_color="FFFFA500", fill_type="solid"),
            "low": PatternFill(start_color="FF90EE90", end_color="FF90EE90", fill_type="solid"),
            "total": PatternFill(start_color="FFD3D3D3", end_color="FFD3D3D3", fill_type="solid"),
            }
 
        for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
            category_cell = row[0]
            category = str(category_cell.value).strip().lower()
            if "critical" in category:
                category_cell.fill = dashboard_fills["critical"]
            elif "high" in category:
                category_cell.fill = dashboard_fills["high"]
            elif "medium" in category:
                category_cell.fill = dashboard_fills["medium"]
            elif "low" in category:
                category_cell.fill = dashboard_fills["low"]
            elif "total" in category:
                category_cell.fill = dashboard_fills["total"]
 
        for sheet in ["Vulnerability Assessment", "Security Issues"]:
            ws = wb[sheet]
            for cell in ws[1]:
                cell.font = Font(bold=True)
 
            severity_col = None
            for i, cell in enumerate(ws[1], start=1):
                if str(cell.value).strip().lower() == "severity":
                    severity_col = i
                    break
 
            if severity_col is None:
                continue
 
            severity_fills = {
                "Critical": PatternFill(start_color="FF800000", end_color="FF800000", fill_type="solid"),
                "High": PatternFill(start_color="FFFF0000", end_color="FFFF0000", fill_type="solid"),
                "Medium": PatternFill(start_color="FFFFA500", end_color="FFFFA500", fill_type="solid"),
                "Low": PatternFill(start_color="FF90EE90", end_color="FF90EE90", fill_type="solid")
 
            }
 
            for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
                cell = row[severity_col - 1]
                val = str(cell.value).strip()
                if val in severity_fills:
                    cell.fill = severity_fills[val]
 
        wb.save(output_file)
        print(f"✅ Saved {output_file}")
 
    except Exception as e:
        print(f"❌ Error processing {csv_file}: {e}")
