target:
	python setup.py install

clean:
	pip uninstall -y cybertop
	rm -fr dist build cybertop.egg-info



