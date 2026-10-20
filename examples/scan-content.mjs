import { scan } from 'codaro-local-check/scan';
console.log(await scan({ file: 'package.json', content: JSON.stringify({ license: 'MIT', dependencies: {} }) }, { allowedLicenses: ['MIT'] }));
