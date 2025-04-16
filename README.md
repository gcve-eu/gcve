# GCVE: Global CVE Allocation System

The [Global CVE (GCVE) allocation system](https://gcve.eu) is a new, decentralized approach to vulnerability identification and numbering, designed to improve flexibility, scalability, and autonomy for participating entities.

While remaining compatible with the traditional CVE system, GCVE introduces GCVE Numbering Authorities (GNAs). GNAs are independent entities that can allocate identifiers without relying on a centralised block distribution system or rigid policy enforcement.

This format is already used in [Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup).  
See an example [here](https://vulnerability.circl.lu/product/651684fd-f2b4-45ac-96d0-e3e484af6113).


## Example of usage

Generating new GCVE-1 entries (CIRCL namespace) by preventing collision with official CVE (GCVE-0):

```python
from gcve import gcve_generator, get_gna_id_by_short_name, to_gcve_id

if CIRCL_GNA_ID := get_gna_id_by_short_name("CIRCL", GCVE_eu):
    existing_gcves = {to_gcve_id(cve) for cve in vulnerabilitylookup.get_all_ids()}
    generator = gcve_generator(existing_gcves, CIRCL_GNA_ID)
    for _ in range(5):
        print(next(generator))
```


## Contact

https://www.circl.lu


## License

GCVE is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)
