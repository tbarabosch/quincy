This directory contains patches to projects that Quincy relies on. 

# Patch: HollowFind

To run HollowFind as a heuristic, you have to patch HollowFind's to output its results as Quincy it expected.

Checkout HollowFind from github

~~~
git clone https://github.com/monnappa22/HollowFind.git
~~~

and apply the patch to commit 58aa3990807154cc8860137754f3bfa92deb644b:

~~~
git apply --stat hollowfind_quincy.patch
~~~

Finally, put the patched version of HollowFind in Volatility's plugin folder.

# Patch: Volatility

You may need to patch Volatility to extract correct thread information. Just run the python script patchVolatilityThreads.py as root:

~~~
sudo python patchVolatilityThreads.py
~~~