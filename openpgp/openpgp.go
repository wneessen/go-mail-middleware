package openpgp

import (
	"bytes"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/helper"
	log "github.com/dhia-gharsallaoui/go-logger"
	"github.com/wneessen/go-mail"
)

// Middleware is the middleware struct for the openpgp middleware
type Middleware struct {
	logger      log.Logger
	certificate []byte
}

// MiddlewareConfig is the confiuration to use in Middleware creation
type MiddlewareConfig struct {
	// Logger is the logger interface implementation that you can inject
	Logger log.Logger
	// the certificate that will be used to encrpt the mails before sending
	Certificate []byte
}

// NewMiddleware returns a new Middlware from a given MiddlewareConfig
func NewMiddleware(cfg *MiddlewareConfig) *Middleware {
	if cfg.Logger != nil {
		return &Middleware{logger: cfg.Logger, certificate: cfg.Certificate}
	}
	return &Middleware{logger: log.NewLogger(&log.LoggerConfiguration{
		Prefix:    "",
		Verbosity: log.WARN,
	})}
}

// Handle is the handler method that satisfies the mail.Middleware interface
func (m *Middleware) Handle(msg *mail.Msg) *mail.Msg {
	if m.certificate == nil {
		m.logger.Fatal("no certifcate provided")
	}
	pp := msg.GetParts()
	for _, part := range pp {
		c, err := part.GetContent()
		if err != nil {
			m.logger.Fatal(err.Error())
		}
		switch part.GetContentType() {
		case mail.TypeTextPlain, mail.TypeTextHTML:
			s, err := helper.EncryptMessageArmored(string(m.certificate), string(c))
			if err != nil {
				m.logger.Fatal(err.Error())
			}
			part.SetContent(s)

		case mail.TypeAppOctetStream:
			s, err := helper.EncryptBinaryMessageArmored(string(m.certificate), c)
			if err != nil {
				m.logger.Fatal(err.Error())
			}
			part.SetContent(s)
		default:
			m.logger.Fatal(fmt.Sprintf("content type %s not implemented", part.GetContentType()))
		}
	}
	ff := msg.GetAttachments()
	msg.SetAttachements(nil)
	for _, f := range ff {
		w := writer{}
		f.Writer(&w)
		b, err := helper.EncryptBinaryMessageArmored(string(m.certificate), w.body)
		if err != nil {
			m.logger.Fatal(err.Error())
		}
		msg.AttachReader(f.Name, bytes.NewReader([]byte(b)))
	}
	return msg
}

type writer struct {
	body []byte
}

func (w *writer) Write(p []byte) (int, error) {
	w.body = p
	return len(p), nil
}
