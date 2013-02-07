require "erb"

module Gd

  class Templater
    
    
    def initialize(options = {})
      if (options[:template_path] != nil) then
        template = File.read(options[:template_path])
      else 
        template = options[:template]
      end
        
      fail "Template for email is not defined" if template == nil
      @erb = ERB.new(template.to_s.gsub(/^  /, ''))
    end
    
    def get_message(data)
      @erb.result(binding)
    end

  end

end