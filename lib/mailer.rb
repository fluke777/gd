require "erb"
require "pony"


module Gd

  class Templater
    
    
    def initialize(template,object,options = {})
      template = File.read(template)
      @erb = ERB.new(template.to_s.gsub(/^  /, ''))
    end
    
    
    
    def get_message(data)
      @erb.result(binding)
    end

  end
  
  module Mailer
   
    def self.mail(options = {})
      begin
        Pony.mail(options)
      rescue
        fail "Email could not be sent"
      end
    end
   
   end
  

end