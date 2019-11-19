# Fiscalia

## Getting started

   - Create python virtual environment, source and install dependencies
   
   ```
   $ virtualenv devel
   $ source devel/bin/activate
   (devel)$ pip install -r requirements
   ```
   
   - Instantiate Mongo DB on a separate terminal or demonize with -d
   
   ```
   $ docker run -p 27017:27017 mongo
   ```
   
   - Initialize environment variables
   
   ```
   $ export FISCALIA_SECRET={SECRET_KEY}   
   ```
   - Run app via gunicorn
   
   ```
   (devel)$ gunicorn app:app --workers=1
   ```