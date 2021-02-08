# Fiscalia

## Getting started
   - Prerequisites:
       * [virtualenv](https://virtualenv.pypa.io/en/latest/installation.html)
       * [podman](https://podman.io/getting-started/installation.html)
       * [python > 3.6](https://www.python.org/downloads/)

   - Clone this repository and navigate to it's directory
   ```bash
   > git clone https://github.con/grafuls/fiscalia
   > cd fiscalia
   ```
     
   - Create python virtual environment, source and install dependencies
   ```bash
   > virtualenv devel
   > source devel/bin/activate
   (devel) > pip install -r requirements.txt
   ```

   - Instantiate Mongo DB on a separate terminal or demonize with -d 
   ```bash
   > podman run -p 27017:27017 mongo
   ```
   
   - Initialize environment variables
   ```bash
  (On LINUX) > export FISCALIA_SECRET="{SECRET_KEY}"
  (On Windows) > setx FISCALIA_SECRET "{SECRET_KEY}"
   ```

   - Run app via gunicorn 
   ```bash
   (devel) > gunicorn app:app --workers=1
   ```

   - Open Web browser and navigate to:
      * http://127.0.0.1:8000
