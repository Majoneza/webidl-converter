from __future__ import annotations
import re
from io import TextIOWrapper
from typing import List, Pattern, Optional, Match

STATEMENT_TERMINATOR = re.compile(r';')
COMMENT = re.compile(r'//.*?\\n|/\*.*?\*/')
OBJECT_STATEMENT_START = re.compile(r'\{')
OBJECT_STATEMENT_END = re.compile(r'\}')

IMPLEMENTS_REGEX = re.compile(r'(?P<name>[a-zA-Z_]\w+)\simplements\s(?P<parent>[a-zA-Z]\w+);')

class CustomDict(dict):
  def __missing__(self, key: str):
    return key

types_map = CustomDict({'byte': 'number', 'octet': 'number', 'short': 'number',
                        'unsigned short': 'number', 'long': 'number', 'unsigned long': 'number',
                        'long long': 'number', 'unsigned long long': 'number', 'float': 'number',
                        'unrestricted float': 'number', 'double': 'number',
                        'unrestricted double': 'number', 'bigint': 'BigInt', 'DOMString': 'string',
                        'ByteString': 'string', 'USVString': 'string', 'object': 'object',
                        'symbol': 'symbol',
                        'byte[]': 'number[]', 'octet[]': 'number[]', 'short[]': 'number[]',
                        'unsigned short[]': 'number[]', 'long[]': 'number[]', 'unsigned long[]': 'number[]',
                        'long long[]': 'number[]', 'unsigned long long[]': 'number[]', 'float[]': 'number[]',
                        'unrestricted float[]': 'number[]', 'double[]': 'number[]',
                        'unrestricted double[]': 'number[]', 'bigint[]': 'BigInt[]', 'DOMString[]': 'string[]',
                        'ByteString[]': 'string[]', 'USVString[]': 'string[]', 'object[]': 'object[]',
                        'symbol[]': 'symbol[]'})

class WebIDLExpression(object):
  _regex: Pattern[str]
  def getTypescript(self) -> str:
    return ''
  @classmethod
  def check(cls, text: str) -> bool:
    match = cls._regex.search(text)
    return match is not None
  @classmethod
  def create(cls, text: str) -> WebIDLExpression:
    return None

class WebIDLObject(WebIDLExpression):
  @classmethod
  def getObjects(cls) -> List[WebIDLObject]:
    return cls.__subclasses__()

class WebIDLEnum(WebIDLObject):
  _regex = re.compile(r'^enum\s(?P<name>\w+)\s\{(?P<data>[^\}]*)\};$')
  def __init__(self, name: str, values: List[str]):
    self.name = name
    self.values = values
  def addValue(self, value: str) -> None:
    self.values.append(value)
  def getTypescript(self) -> str:
      return 'export type {0} = {1};\n'.format(self.name,
        " | ".join(["\"{0}\"".format(value) for value in self.values]))
  @classmethod
  def create(cls, text: str) -> WebIDLEnum:
    groups = cls._regex.search(text).groupdict()
    return cls(groups['name'], [group.strip()[1:-1] for group in groups['data'].split(',')])

class WebIDLTypedef(WebIDLObject):
  _regex = re.compile(r'^typedef\s(?P<type>.+?)\s(?P<name>\w+);$')
  def __init__(self, name: str, type: str):
    self.name = name
    self.type = type
  def getTypescript(self) -> str:
    return 'export type {0} = {1};\n'.format(self.name, types_map[self.type])
  @classmethod
  def create(cls, text: str) -> WebIDLTypedef:
    groups = cls._regex.search(text).groupdict()
    return cls(groups['name'], groups['type'])

class WebIDLDictionaryProperty(WebIDLExpression):
  _regex = re.compile(r'^(?P<type>.+?)(?P<optional>\?)?\s(?P<name>\w+)(\s?=\s?(?P<value>.+?))?;$')
  def __init__(self, name: str, type: str, is_optional: bool):
    self.name = name
    self.type = type
    self.is_optional = is_optional
  def getTypescript(self) -> str:
    return '{0}{1}: {2};'.format(self.name, '?' if self.is_optional else '', types_map[self.type])
  @classmethod
  def create(cls, text: str) -> WebIDLDictionaryProperty:
    groups = cls._regex.search(text).groupdict()
    return cls(groups['name'], groups['type'], bool(groups['optional']))

class WebIDLDictionary(WebIDLObject):
  _regex = re.compile(r'^dictionary\s(?P<name>\w+)(\s?:\s?(?P<parents>[^\{]+?))?\s?\{(?P<data>[^\}]*)\};$')
  def __init__(self, name: str, parents: List[str], properties: List[WebIDLDictionaryProperty]):
    self.name = name
    self.parents = parents
    self.properties = properties
  def addProperty(self, property: WebIDLDictionaryProperty) -> None:
    self.properties.append(property)
  def addParent(self, parent: str) -> None:
    self.parents.append(parent)
  def getTypescript(self) -> str:
    return 'export interface {0}{1} {b_open}\n{2}\n{b_close}\n'.format(self.name,
      '' if len(self.parents) == 0 else ' extends ' + ', '.join(self.parents),
      "\n".join(['\t{0}'.format(prty.getTypescript()) for prty in self.properties]),
      b_open='{', b_close='}')
  @classmethod
  def create(cls, text: str) -> WebIDLDictionary:
    groups = cls._regex.search(text).groupdict()
    return cls(groups['name'],
      [parent.strip() for parent in groups['parents'].split(',')] if groups['parents'] else [],
      [WebIDLDictionaryProperty.create(entry + ';') for entry in groups['data'].split(';')[:-1] if WebIDLDictionaryProperty.check(entry + ';')])

class WebIDLInterfaceProperty(WebIDLExpression):
  _regex = re.compile(r'^(\[(?P<attributes>.+?)(?<!\[)\]\s?)?(?P<static>static\s)(?P<const>const\s)?(?P<readonly>readonly\s)?(?P<attribute>attribute\s)?(?P<type>[^\?]+?)(?P<optional>\?)?\s(?P<name>\w+)(\s?=\s?(?P<value>.+?))?(\sraises\s?\((?P<exception>[^\)]+)\))?;$')
  def __init__(self, name: str, type: str, is_static: bool, is_const: bool, is_readonly: bool, is_optional: bool):
    self.name = name
    self.type = type
    self.is_static = is_static
    self.is_const = is_const
    self.is_readonly = is_readonly
    self.is_optional = is_optional
  def getTypescript(self) -> str:
    return '{0}{1}{2}{3}: {4};'.format('static ' if self.is_const else '',
      'readonly ' if self.is_readonly else '', self.name, '?' if self.is_optional else '', types_map[self.type])
  @classmethod
  def create(cls, text: str) -> WebIDLInterfaceProperty:
    groups = cls._regex.search(text).groupdict()
    return cls(groups['name'], groups['type'], bool(groups['static']), bool(groups['const']),
      bool(groups['readonly']), bool(groups['optional']))

class WebIDLFunctionArgument(WebIDLExpression):
  _regex = re.compile(r'^(\[(?P<attributes>.+?)(?<!\[)\]\s?)?(?P<optional>optional\s)?(?P<type>.+?)\??\s(?P<name>\w+)$')
  def __init__(self, name: str, type: str, is_optional: bool):
    self.name = name
    self.type = type
    self.is_optional = is_optional
  def getTypescript(self) -> str:
    return '{0}{1}: {2}'.format(self.name, '?' if self.is_optional else '', types_map[self.type])
  @classmethod
  def create(cls, text: str) -> WebIDLFunctionArgument:
    groups = cls._regex.search(text).groupdict()
    return cls(groups['name'], groups['type'], bool(groups['optional']))

class WebIDLInterfaceFunction(WebIDLExpression):
  _regex = re.compile(r'^(?P<static>static\s)?(?P<keyword>(?:getter|setter|deleter|stringifier)\s)?(?P<type>.+?)\s(?P<name>\w+)?\((?P<args>[^\)]+)?\)(\s?raises\s?\((?P<exception>.+?)\))?;$')
  def __init__(self, name: str, returnType: str, arguments: List[WebIDLFunctionArgument], is_optional: bool):
    self.name = name
    self.returnType = returnType
    self.arguments = arguments
    self.is_optional = is_optional
  def getTypescript(self) -> str:
    return '{0}{1}({2}): {3};'.format(self.name, '?' if self.is_optional else '',
      ", ".join([arg.getTypescript() for arg in self.arguments]), types_map[self.returnType])
  @classmethod
  def create(cls, text: str) -> WebIDLInterfaceFunction:
    groups = cls._regex.search(text).groupdict()
    return cls(groups['name'], groups['type'],
      [WebIDLFunctionArgument.create(arg.strip()) for arg in groups['args'].split(',') if WebIDLFunctionArgument.check(arg.strip())] if groups['args'] else [],
      False)

class WebIDLInterface(WebIDLObject):
  _regex = re.compile(r'^(\[(?P<attributes>.+?)(?<!\[)\]\s?)?interface\s(?P<name>\w+)(\s?:\s?(?P<parents>.+?))?\s?\{(?P<data>[^\}]*)\};$')
  _nointerface_attribute = re.compile(r'^NoInterfaceObject$')
  _callback_attribute = re.compile(r'^Callback(\s?=\s?(?P<value>\w+))?$')
  _constructor_attribute = re.compile(r'^Constructor\((?P<args>[^\)]+)?\)$')
  def __init__(self, name: str, parents: List[str], attributes: List[str], properties: List[WebIDLInterfaceProperty], functions: List[WebIDLInterfaceFunction]):
    self.name = name
    self.parents = parents
    self.attributes = attributes
    self.properties = properties
    self.functions = functions
  def addProperty(self, property: WebIDLInterfaceProperty):
    self.properties.append(property)
  def addParent(self, parent: str):
    self.parents.append(parent)
  def _hasAttribute(self, pattern: Pattern[str]) -> bool:
    for attr in self.attributes:
      if pattern.search(attr) is not None:
        return True
    return False
  def _getAttribute(self, pattern: Pattern[str]) -> Optional[Match[str]]:
    for attr in self.attributes:
      match = pattern.search(attr)
      if match is not None:
        return match
    return None
  @property
  def _isClass(self) -> bool:
    return not self._hasAttribute(__class__._nointerface_attribute) or any([prty.is_const for prty in self.properties])
  def _getConstructor(self) -> str:
    groups = self._getAttribute(__class__._constructor_attribute).groupdict()
    return 'constructor({0});'.format(', '.join(
      [WebIDLFunctionArgument.create(arg.strip()).getTypescript() for arg in groups['args'].split(',') if WebIDLFunctionArgument.check(arg.strip())] if groups['args'] else []))
  def getTypescript(self) -> str:
    if self._hasAttribute(__class__._callback_attribute):
      groups = self._getAttribute(__class__._callback_attribute).groupdict()
      if len(self.properties) == 0:
        if groups['value']:
          if groups['value'] == 'FunctionOnly' and len(self.functions) == 1:
            return 'export {0} {1}{2} {b_open}\n\t({3}): {4};\n{b_close}\n'.format('class' if self._isClass else 'interface',
              self.name, '' if len(self.parents) == 0 else ' extends ' + ', '.join(self.parents),
              ', '.join([arg.getTypescript() for arg in self.functions[0].arguments]), self.functions[0].returnType,
              b_open='{', b_close='}')
          else:
            print('Error: {0}'.format(self.name))
        else:
          # All functions should be optional
          for func in self.functions:
            func.is_optional = True
    return 'export {0} {1}{2} {b_open}\n{3}{4}\n{b_close}\n'.format('class' if self._isClass else 'interface',
      self.name, '' if len(self.parents) == 0 else ' extends ' + ', '.join(self.parents),
      '\t{0}\n'.format(self._getConstructor()) if self._hasAttribute(__class__._constructor_attribute) else '',
      '\n'.join(['\t' + obj.getTypescript() for obj in [*self.properties, *self.functions]]),
      b_open='{', b_close='}')
  @classmethod
  def create(cls, text: str) -> WebIDLInterface:
    groups = cls._regex.search(text).groupdict()
    return cls(groups['name'],
      [parent.strip() for parent in groups['parents'].split(',')] if groups['parents'] else [],
      [attribute.strip() for attribute in groups['attributes'].split(',')] if groups['attributes'] else [],
      [WebIDLInterfaceProperty.create(entry + ';') for entry in groups['data'].split(';')[:-1] if WebIDLInterfaceProperty.check(entry + ';')],
      [WebIDLInterfaceFunction.create(entry + ';') for entry in groups['data'].split(';')[:-1] if WebIDLInterfaceFunction.check(entry + ';')])

def findWebIDLObject(objects: List[WebIDLObject], name: str) -> Optional[WebIDLObject]:
  for obj in objects:
    if obj.name == name:
      return obj
  return None

def convert(inputFile: TextIOWrapper, outputFile: TextIOWrapper) -> None:
  objects: List[WebIDLObject] = []
  lines: List[str] = []
  original_line: str = '-1'
  line: str = ''
  lineCounter = 1
  started_object_statement = False
  while original_line != '':
    try:
      original_line = inputFile.readline()
      line = original_line.strip()
    except:
      print('Line {0} skipped'.format(lineCounter))
    lines.append(line)
    if not started_object_statement:
      if OBJECT_STATEMENT_START.search(line):
        started_object_statement = True
    if started_object_statement:
      if OBJECT_STATEMENT_END.search(line):
        started_object_statement = False
    if not started_object_statement:
      if STATEMENT_TERMINATOR.search(line):
        matched = False
        line = COMMENT.sub('', ''.join(lines)).strip()
        for obj in WebIDLObject.getObjects():
          if obj.check(line):
            matched = True
            objects.append(obj.create(line))
            break
        if IMPLEMENTS_REGEX.search(line):
          matched = True
          groups = IMPLEMENTS_REGEX.search(line).groupdict()
          obj: WebIDLInterface | None = findWebIDLObject(objects, groups['name'])
          if obj is not None:
            obj.addParent(groups['parent'])
          else:
            print('Failed to add parent {0} to object {1}'.format(groups['parent'], groups['name']))
        if not matched:
          print('Unable to match line: {0}'.format(lineCounter))
        lines.clear()
    lineCounter += 1
  for obj in objects:
    outputFile.write(obj.getTypescript())


def main() -> None:
  inputName = input("Input file name: ")
  outputName = input("Output file name: ")
  with open(inputName, "r") as inputFile:
    with open(outputName, "x") as outputFile:
      convert(inputFile, outputFile)


if __name__ == '__main__':
  main()
