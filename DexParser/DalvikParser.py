import zipfile
import sys
import struct

class Dalvik:
        
    def __init__(self, filestream):
        self.source = filestream

        #Header
        self.header = Dalvik_Header(self.source)
        self.strings = Strings_Table(self.source,self.header.string_table_offset,self.header.string_table_size)
        self.types = Type_Table(self.source,self.header.type_table_offset,self.header.type_table_size,self.strings.strings)
        self.prototypes = Proto_Table(self.source,self.header.proto_table_offset,self.header.proto_table_size,self.strings.strings,self.types.types)
        self.fields = Field_Table(self.source,self.header.field_table_offset,self.header.field_table_size,self.strings.strings,self.types.types)
        self.methods = Method_Table(self.source,self.header.method_table_offset,self.header.method_table_size,self.strings.strings,self.types.types,self.prototypes.prototypes)
        self.classes = Class_Table(self.source,self.header.class_table_offset,self.header.class_table_size,self.strings.strings,self.types.types)

    @classmethod
    def fromfilename(cls, filename):
        handle=file(filename,'rb')
        tmpsource=handle.read()
        handle.close()
        return cls(tmpsource)

    def getFileLis(self):
        auxclas = []
        for classitem in dex.classes.classes:
            flag = 0
            for aux in auxclas:
                if aux == classitem['source_file']:
                    flag = 1
            if flag == 0:
                auxclas.append(classitem['source_file'])
        return auxclas
    
    def getClassByFile(self, filename, top=False, acces=False):
        auxclas = []
        for classitem in dex.classes.classes:
            if classitem['class'].find("$") < 0 or top:
                if classitem['source_file'] == filename:
                    if classitem['acces'] != "" or acces:
                        auxclas.append(classitem)
        return auxclas
    
    def getSubClasses(self,classname, filename):
        auxclas = []
        for classitem in dex.classes.classes:
            if classitem['class'].find(classname.replace(";","")+"$") >= 0:
                if classitem['source_file'] == filename:
                    auxclas.append(classitem)
        return auxclas
    
    def getClassMethod(self,classname, top = False):
        methods = []
        for method in dex.methods.methods:
            if method['class'].find(classname) >= 0:
                if method['class'].find("$") < 0 or top: 
                    methods.append(method)
        return methods

    def getClassFields(self,classname, top = False):
        fields = []
        for field in dex.fields.fields:
            if field['class'].find(classname) >= 0:
                if field['class'].find("$") < 0 or top: 
                    fields.append(field)
        return fields
        
    
class Dalvik_Header:
    def __init__(self, source):
        self.magic = source[0:8].replace("\n","\\n").replace("\0","\\0")
        self.checksum = struct.unpack("<I", source[8:12])[0]
        self.checksumHex = source[8:12].encode('hex')
        self.sha_sign = source[12:32].encode('hex')
        self.file_size = struct.unpack("<I", source[32:36])[0]
        self.header_size = struct.unpack("<I", source[36:40])[0]
        self.endian_tag = source[40:44].encode('hex')
        self.link_size = struct.unpack("<I", source[44:48])[0]
        self.link_offset = struct.unpack("<I", source[48:52])[0]
        self.map_offset= struct.unpack("<I", source[52:56])[0]
        self.string_table_size= struct.unpack("<I", source[56:60])[0]
        self.string_table_offset= struct.unpack("<I", source[60:64])[0]
        self.type_table_size= struct.unpack("<I", source[64:68])[0]
        self.type_table_offset= struct.unpack("<I", source[68:72])[0]
        self.proto_table_size= struct.unpack("<I", source[72:76])[0]
        self.proto_table_offset= struct.unpack("<I", source[76:80])[0]
        self.field_table_size= struct.unpack("<I", source[80:84])[0]
        self.field_table_offset= struct.unpack("<I", source[84:88])[0]
        self.method_table_size= struct.unpack("<I", source[88:92])[0]
        self.method_table_offset= struct.unpack("<I", source[92:96])[0]
        self.class_table_size= struct.unpack("<I", source[96:100])[0]
        self.class_table_offset= struct.unpack("<I", source[100:104])[0]
        self.data_table_size= struct.unpack("<I", source[104:108])[0]
        self.data_table_offset= struct.unpack("<I", source[108:112])[0]

class Strings_Table:
    def __init__(self, source, offset,size):
        self.strings = []
        for i in range(0,size):
            temp_offset = struct.unpack("<I", source[offset+(i*4):offset+((i+1)*4)])[0]
            string_size = struct.unpack("<B", source[temp_offset])[0]
            temp_limit = temp_offset + string_size +1
            self.strings.append(source[temp_offset+1:temp_limit])
                                     
class Type_Table:
    def __init__(self, source, offset,size,strings):
        self.types = []
        for i in range(0,size):
            string_id = struct.unpack("<I", source[offset+(i*4):offset+((i+1)*4)])[0]
            self.types.append(strings[string_id])

class Proto_Table:
    def __init__(self, source, offset,size,strings,types):
        self.prototypes = []
        for i in range(0,size):
            string_id = struct.unpack("<I", source[offset+(i*12):offset+((i*12)+4)])[0]
            type_id = struct.unpack("<I", source[offset+((i*12)+4):offset+((i*12)+8)])[0]
            parameters_off = struct.unpack("<I", source[offset+((i*12)+8):offset+((i*12)+12)])[0]
            temp_proto = {
                'type': types[type_id],
                'name': strings[string_id],
                'param_offset': parameters_off
                }
            self.prototypes.append(temp_proto)

class Field_Table:
    def __init__(self, source, offset,size,strings,types):
        self.fields = []
        for i in range(0,size):
            class_id = struct.unpack("<H", source[offset+(i*8):offset+((i*8)+2)])[0]
            type_id = struct.unpack("<H", source[offset+((i*8)+2):offset+((i*8)+4)])[0]
            string_id = struct.unpack("<I", source[offset+((i*8)+4):offset+((i*8)+8)])[0]
            temp_field = {
                'class': types[class_id],
                'type': types[type_id],
                'name': strings[string_id]
                }
            self.fields.append(temp_field)

class Method_Table:
    def __init__(self, source, offset,size,strings,types,proto):
        self.methods = []
        for i in range(0,size):
            type_id = struct.unpack("<H", source[offset+(i*8):offset+((i*8)+2)])[0]
            proto_id = struct.unpack("<H", source[offset+((i*8)+2):offset+((i*8)+4)])[0]
            string_id = struct.unpack("<I", source[offset+((i*8)+4):offset+((i*8)+8)])[0]
            temp_method = {
                'class': types[type_id],
                'proto': proto[proto_id],
                'name': strings[string_id]
                }
            self.methods.append(temp_method)

class Class_Table:
    def __init__(self, source, offset,size,strings,types):
        self.classes = []
        for i in range(0,size):
            class_id = struct.unpack("<I", source[offset+(i*32):offset+((i*32)+4)])[0]
            access_flags = struct.unpack("<I", source[offset+((i*32)+4):offset+((i*32)+8)])[0]
            superclass_id = struct.unpack("<I", source[offset+((i*32)+8):offset+((i*32)+12)])[0]
            interfaces_off = struct.unpack("<I", source[offset+((i*32)+12):offset+((i*32)+16)])[0]
            source_file_id = struct.unpack("<I", source[offset+((i*32)+16):offset+((i*32)+20)])[0]
            annotations_off = struct.unpack("<I", source[offset+((i*32)+20):offset+((i*32)+24)])[0]
            class_data_off = struct.unpack("<I", source[offset+((i*32)+24):offset+((i*32)+28)])[0]
            static_values_off = struct.unpack("<I", source[offset+((i*32)+28):offset+((i*32)+32)])[0]
            if source[offset+((i*32)+16):offset+((i*32)+20)].encode('hex') != "ffffffff":
                source_file_name = strings[source_file_id]
            else:
                try:
                    auxclassparts = types[class_id].split("/")
                    source_file_name = auxclassparts[len(auxclassparts)-1].split(";")[0].split("$")[0]+".java"
                except:
                    source_file_name = "UnknownFile#%s.java" % (i)  
            temp_class = {
                'class': types[class_id],
                'acces': self.access_flag_value(access_flags),
                'parent': types[superclass_id],
                'source_file': source_file_name
                    }
            self.classes.append(temp_class)

    def access_flag_value(self,access_flags):
        value = ""
        if access_flags & 1:
            value = value + "public "
        if access_flags & 2:
            value = value + "private "
        if access_flags & 4:
            value = value + "protected "
        if access_flags & 8:
            value = value + "static "
        if access_flags & 16:
            value = value + "final "
        if access_flags & 32:
            value = value + "synchronized "
        if access_flags & 64:
            value = value + "volatile "
        if access_flags & 64:
            value = value + "bridge "
        if access_flags & 128:
            value = value + "transient "
        if access_flags & 128:
            value = value + "varargs "
        if access_flags & 256:
            value = value + "native "
        if access_flags & 512:
            value = value + "interface "
        if access_flags & 1024:
            value = value + "abstract "
        if access_flags & 2048:
            value = value + "strict "
        if access_flags & 4096:
            value = value + "synthethic "
        if access_flags & 8196:
            value = value + "annotation "
        if access_flags & 16384:
            value = value + "enum "
        if access_flags & 32768:
            value = value + ""
        if access_flags & 65536:
            value = value + "constructor "
        if access_flags & 131072:
            value = value + "declared synchronized "
        return value


class AndroidApp:
    def __init__(self, filename):
        self.isvalidAPK = False
        try:
            z = zipfile.ZipFile(filename, "r")
            counter = 0
            for filename in z.namelist():
                if filename.find("classes.dex") == 0 or filename.find("AndroidManifest.xml") == 0:
                    counter = counter + 1
                    if filename.find("classes.dex") == 0:
                        self.dex = Dalvik(z.read(filename))
            if counter >= 2:
                self.isvalidAPK =True

        except:
            self.isvalidAPK =False


