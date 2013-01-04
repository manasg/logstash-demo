require 'grok-pure'

grok = Grok.new

grok.add_patterns_from_file("/home/manas/logstash-1.1.7-monolithic/patterns/grok-patterns")

pattern = '%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] \\"(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|-)\\" %{NUMBER:response} (?:%{NUMBER:bytes}|-) (?:%{QS:referrer}|-) \\"%{GREEDYDATA:agent}\\" \\"%{IPORHOST:host}\\" %{DATA:gae_stats} instance=%{GREEDYDATA:gae_instance}'

grok.add_pattern("GAEREQUESTLOG", pattern)
grok.compile(pattern)

logfile = File.open('gae_request.log')
logfile.each do |logline|
    puts logline
    result = grok.match(logline)
    puts result.captures if result
    puts
end


