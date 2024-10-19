package controller

type errorIs func(err error) bool

func ignoreErr(err error, is ...errorIs) error {
	for _, f := range is {
		if f(err) {
			return nil
		}
	}
	return err
}
