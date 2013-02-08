require "erb"

module Gd

  class Templater
    
    def json
      @json
    end
    
    def subject
      @json["subject"] || ""
    end
    
    def from
      @json["from"] || "ps@gooddata.com"
    end
    
    def initialize(json)
      @json = json
      if (!json["template_path"].empty?) then
        puts "path"
        text = File.read(json["template_path"])
      else 
        puts "text"
        text = json["template"]
      end
        
      fail "Template for email is not defined" if text.empty? 
      @erb = ERB.new(text.to_s.gsub(/^  /, ''))
    end
    
    def get_message(data)
      @erb.result(binding)
    end

  end

end