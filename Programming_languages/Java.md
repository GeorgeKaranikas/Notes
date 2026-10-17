# Jar Files


- Stands for Java Archive (JAR) and end with `.jar`

- They follow the zip file format

- Besides the .java files, .class files, etc.  it also contains metadata.

- They must contain exactly one manifest file with path name `META-INF/MANIFEST.MF `

### Creating jars


```bash
$ jar cf jar-file input-file(s)
```

- c is for create
- f is for output file
- input-files could also be a directory


- By default the jar command also creates a manifest file with path name META-INF/MANIFEST.MF.

- replace the manifest file with:

```bash
$ jar cmf jar-file existing-manifest input-file(s)
```

### Viewing the Contents

```bash
$ jar tf jar-file
```

### Extracting Contents of JAR

```bash
$ jar xf jar-file [archived-file(s)]
```

-  If argument `archive-files` is not present, the Jar tool will extract all the files in the archive.

- The original JAR file remains unchanged.


## Manifest file

### Modifying a Manifest File

- You can modify the manifest file during the creation of the jar file.

```bash
$ jar cfm jar-file manifest-addition-file input-file(s)
```

- manifest-addition is the name (or path and name) of the existing text file whose contents you want to add to the contents of JAR file's manifest.

### Setting the entry point


- The entry point in a jar file needs to be:
    - A class in the jar file with a classname appended to the manifest file like: `Main-Class: classname`

    - A method with the signature `public static void main(String[] args)` in this class.

- So create Manifest.txt:

```
Main-Class: Package.Class (CRLF!)

```

- Then create the JAR

```bash
$ jar cfm Project.jar Manifest.txt Package/*.class
```

- Run this with:

```bash
$ java -jar Project.jar
```

- Or simply use the `e` flag on jar

```bash
$ jar cfe Project.jar Package.Main Package/*.class
```

