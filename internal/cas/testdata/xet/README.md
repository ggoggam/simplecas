Reference vectors from the Xet protocol's
[xet-team/xet-spec-reference-files](https://huggingface.co/datasets/xet-team/xet-spec-reference-files):

- `reference.chunks` is `Electric_Vehicle_Population_Data_20250917.csv.chunks`:
  the hash and length of each chunk Xet cuts that file into, in order. All of
  them form one xorb, `eea25d6ee393ccae385820daed127b96ef0ea034dfb7cf6da3a950ce334b7632`,
  and the file's Xet hash is `118a53328412787fee04011dcf82fdc4acf3a4a1eddec341c910d30a306aaf97`.
- `099cb228….chunk` is one chunk of that file, named by its chunk hash.

The CSV itself (63 MB) and its serialized xorb are not checked in. To check
the chunker and the xorb reader against them too, download them into a
directory and set `SIMPLECAS_XET_REFERENCE_DIR` to it.
