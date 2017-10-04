target:
	python setup.py install test

clean:
	pip uninstall -y cybertop
	rm -fr dist build cybertop.egg-info



