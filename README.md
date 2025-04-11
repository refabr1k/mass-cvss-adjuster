# mass-cvss-adjuster
Using NIST API (https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}) to adjust CVSS scoring for list of CVES. e.g. Nessus scan results, pentest reports with multiple CVEs but you are adjusting the impact based on its Attack Vector.


# How it works

1. Adjust Attack Vector field in script e.g. Changing it to "A" will reduce all CVEs vectors provided by (CVSS) "A".

```
AV_ADJUST = "A"  # Change to "A" for Adjacent or "L" for Local
```

2. Supply a list of CVES

Note: The script just passes the CVE number to NIST API, and gets a response on the CVSS vector, then it adjusts the AV. 

# limitations / to-do

- Free use of the NIST API has limitations eg. only allow a limitated number of queries in 30 seconds. The script was adjusted to slow down each request so it may take time. Alternatively, sign up for a API account and make adjustments to the code to make queries faster
- Use with "trust but verify" mindset, the tool does not take into consideration of the nature of the exploit and is simply changing the AV. eg. if its a local buffer overflow (changing it from a Local attack vector to Network will lead to an inaccurate severity rating.
