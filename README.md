
## About

Code duplication is a big issue. As developers move from from project to project we often copy and paste snippets of code between projects. While this is quick and easy its very hard to maintain.

This project is intended to act as a place where front end developers can store and share useful snippets of code.

## Usage

Install via `npm` as you would with any other package by supplying both the repo URL and branch or tag reference. In the example below the tag *v0.0.1* is used.

```console
npm i -S @bcgov/common-web-utils
```

You can also directly add it to your `package.json` file by inserting the following line into your dependencies section:

```json
"@bcgov/nodejs-common-utils": "git+https://git@github.com/bcgov/common-web-utils.git#v0.0.1",
```

Once you installed you can can use it like any other module:

```javascript
import { ImplicitAuthManager } from '@bcgov/common-web-utils';
```
### Further Documentation

[Implicit Auth Manager](./docs/ImplicitAuthManger.md)

## Project Status / Goals / Roadmap

This project is **active**. 


## Getting Help or Reporting an Issue

Send a note to bcdevexchange@gov.bc.ca and you'll get routed to the right person to help you out.


## How to Contribute

Create a pull request with your code. Its really that simple.

\* If you are including a Code of Conduct, make sure that you have a [CODE_OF_CONDUCT.md](SAMPLE-CODE_OF_CONDUCT.md) file, and include the following text in here in the README:\*
"Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms."

## License

    Copyright 2018 Province of British Columbia

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at 

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons Licence" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/80x15.png" /></a><br /><span xmlns:dct="http://purl.org/dc/terms/" property="dct:title">nodejs-common-utils</span> by <span xmlns:cc="http://creativecommons.org/ns#" property="cc:attributionName">the Province of British Columbia</span> is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.

[export-xcarchive]: https://github.com/bcdevops/mobile-cicd-api/raw/develop/doc/images/export-xcarchive.gif "Prepare & Export xcarchive"
