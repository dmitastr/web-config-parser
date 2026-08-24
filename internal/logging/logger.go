package logging

import "github.com/sirupsen/logrus"

func New(level logrus.Level) *logrus.Logger {
	l := logrus.New()
	l.SetLevel(level)
	l.SetFormatter(&logrus.JSONFormatter{})
	return l
}
