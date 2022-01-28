import Handlebars from 'handlebars'

export class EmailError extends Error {
  constructor (code, msg) {
    if (!EmailError.Codes[code]) {
      throw new Error(`Invalid Email error code ${code}`)
    }
    super(msg || EmailError.Codes[code])
    this.code = code
  }

  static Codes = {
    InvalidMessage: 'Email message is invalid',
    InvalidAddress: 'Email address is invalid',
    NoRecipient: 'Email message without recipient',
    NoContent: 'Email message with neither subject nor body or template',
    TemplateError: 'Email template processing failed'
  }
}

function EmailAddress (string) {
  const _isValidEmailAddress = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  if (!_isValidEmailAddress.test(string)) {
    throw new EmailError('InvalidAddress')
  }
  return string
}

const EmailTemplates = {}

export function registerTemplate (name, handlebarsCode) {
  try {
    EmailTemplates[name] = Handlebars.compile(handlebarsCode)
  } catch (err) {
    console.debug(err)
    throw new EmailError('TemplateError', err.msg)
  }
}

class EmailMessage extends Object {
  constructor (props) {
    Object.assign(this, props)
    
    if (!!this.to) {
      throw new EmailError('NoRecipient')
    }
    if (! Array.isArray(this.to)) {
      this.to = [this.to]
    }
    this.to = this.to.map(s => EmailAddress(s))
    if (this.cc && ! Array.isArray(this.cc)) {
      this.cc = [this.cc]
    }
    this.cc = (this.cc || []),map(s => EmailAddress(s))
    if (this.bcc && ! Array.isArray(this.bcc)) {
      this.bcc = [this.bcc]
    }
    this.bcc = (this.bcc || []),map(s => EmailAddress(s))
    
    if (! (this.subject || this.body || this.template)) {
      throw new Error('NoContent')
    }
    this.subject = this.subject || 'Message from Maritime Identity Registry'
    if (this.template && !this.body) {
      try {
        this.body = EmailTemplates[this.template](this)
      } catch (err) {
        throw new (EmailError('TemplateError'), err.msg)
      }
    }
  }

}

class ConsoleMailer extends Object {
  constructor (log = console) {
    this.log = log
  }

  send ( emailMessage ) {
    console.info(`\n
    To: ${emailMessage.to.join(', ')}\n
    Subject: ${emailMessage.subject}\n
    --------------------------------\n
    ${this.text || this.body}\n 
    `)
  }
}

const agents = {
  ConsoleMailer
}

const agent = new agents[process.env['EMAIL_AGENT'] || 'ConsoleMailer']()

export function send ( emailMessage = {}) {
  const msg = new EmailMessage(emailMessage)
  agent.send(msg)
}

