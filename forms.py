from flask_wtf import FlaskForm
from wtforms import DateField, DecimalField, IntegerField, StringField, SelectField, SubmitField, TelField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, Regexp, NumberRange
import re

class ProveedorForm(FlaskForm):
    def sanitize_string(value):
        """ Elimina espacios extra y caracteres no deseados """
        if value:
            value = value.strip()  # Quita espacios en los extremos
            value = re.sub(r'[<>]', '', value)  # Evita etiquetas HTML/JS
        return value
    
    nombre = StringField("Nombre", validators=[
        DataRequired(message="El nombre es obligatorio"),
        Length(min=3, max=150, message="Debe tener entre 3 y 150 caracteres")
    ])
    
    direccion = StringField("Dirección", validators=[
        DataRequired(message="La dirección es obligatoria"),
        Length(max=255, message="Máximo 255 caracteres")
    ])
    
    telefono = TelField("Teléfono", validators=[
        DataRequired(message="El teléfono es obligatorio"),
        Regexp(r'^\d{10}$', message="Debe contener exactamente 10 dígitos numéricos")
    ])
    
    correo = StringField("Correo", validators=[
        DataRequired(message="El correo es obligatorio"),
        Email(message="Formato de correo inválido")
    ])
    
    vendedor = SelectField("Vendedor", choices=[("Principal", "Principal"), ("Secundario", "Secundario")], validators=[
        DataRequired(message="Debe seleccionar un tipo de vendedor")
    ])
    
    empresa = StringField("Empresa", validators=[
        DataRequired(message="La empresa es obligatoria"),
        Length(max=150, message="Máximo 150 caracteres")
    ])
    
    def process_formdata(self, valuelist):
        """ Sanitiza todos los campos antes de validarlos """
        if valuelist:
            self.data = self.sanitize_string(valuelist[0])

    submit_agregar = SubmitField("Agregar")
    submit_modificar = SubmitField("Modificar")
    submit_eliminar = SubmitField("Eliminar")

class MateriaForm(FlaskForm):
    nombreProducto = StringField('Nombre del Producto', validators=[DataRequired(), Length(max=200)])
    cantidad = DecimalField('Cantidad', validators=[DataRequired(), NumberRange(min=0)])

class CompraForm(FlaskForm):
    proveedor = IntegerField('ID del Proveedor', validators=[DataRequired()])
    total = DecimalField('Total', validators=[DataRequired(), NumberRange(min=0)])
    codigoUsuario = StringField('Código de Usuario', validators=[DataRequired(), Length(max=50)])  # Agregar esto


class DetalleCompraForm(FlaskForm):
    idCompra = IntegerField('ID de la Compra')  # Agregar esto para relacionarlo
    nombreProducto = StringField('Nombre del Producto', validators=[DataRequired(), Length(max=200)])
    presentacion = StringField('Presentación', validators=[DataRequired(), Length(max=100)])
    cantidad = DecimalField('Cantidad', validators=[DataRequired(), NumberRange(min=0)])



#ANDREA ---------------------------------------------------------------------------------------
class RecetaForm(FlaskForm):

    nombreGalleta = StringField('Nombre de la Galleta', validators=[DataRequired(), Length(max=255)])

     # Campo de Harina
    cmbHarina = SelectField('Ingrediente 1', choices=[('Harina', 'Harina')], validators=[DataRequired()])
    cantHar = SelectField('Cantidad de Harina', choices=[('2 tazas', '2 tazas')], validators=[DataRequired()])

    # Campo de Mantequilla
    cmbMantequilla = SelectField('Ingrediente 2', choices=[('Mantequilla', 'Mantequilla')], validators=[DataRequired()])
    cantMan = SelectField('Cantidad Mantequilla', choices=[('1/2 taza derritida', '1/2 taza derritida')], validators=[DataRequired()])

    # Campo de Azúcar
    cmbAzucar = SelectField('Ingrediente 3', choices=[('Azúcar', 'Azúcar')], validators=[DataRequired()])
    cantAzur = SelectField('Cantidad de Azúcar', choices=[('3/4 taza ', '3/4 taza ')], validators=[DataRequired()])


    # Campo de Huevo
    cmbHuevo = SelectField('Ingrediente 4', choices=[('Huevo', 'Huevo')], validators=[DataRequired()])
    cantHuv = SelectField('Cantidad de Huevo', choices=[('1 huevo', '1 huevo')], validators=[DataRequired()])

    # Campo de Vainilla
    cmbVainilla = SelectField('Ingrediente 5', choices=[('Vainilla', 'Vainilla')], validators=[DataRequired()])
    cantVain = SelectField('Cantidad de Vainilla', choices=[('1 cucharadita ', '1 cucharadita ')], validators=[DataRequired()])

    # Campo de Polvo de Hornear
    cmbPolvo = SelectField('Ingrediente 6', choices=[('Polvo de Hornear', 'Polvo de Hornear')], validators=[DataRequired()])
    cantHor = SelectField('Cantidad de Polvo de Hornear', choices=[('1/2 cucharadita ', '1/2 cucharadita ')], validators=[DataRequired()])

    # Campo de Sal
    cmbSal = SelectField('Ingrediente 7', choices=[('Sal', 'Sal')], validators=[DataRequired()])
    cantSal = SelectField('Cantidad de Sal', choices=[('1/4 cucharadita ', '1/4 cucharadita ')], validators=[DataRequired()])

    # Campo de Leche
    cmbLe = SelectField('Ingrediente 8', choices=[('Leche', 'Leche')], validators=[DataRequired()])
    cantLech = SelectField('Cantidad de Leche', choices=[('2 Tazas', '2 Tazas')], validators=[DataRequired()])


    # Campo para el ingrediente Adicional
    adicional = StringField('Ingrediente Adicional', validators=[DataRequired(), Length(max=255)])
    cantAdicional = StringField('Cantidad del Ingrediente', validators=[Length(max=150)])

    # Campo para el procedimiento
    procedimiento = TextAreaField('Procedimiento', validators=[DataRequired()])

    # SelectFields para el Estatus
    estatus = SelectField('Estatus', choices=[('Activo', 'Activo'), ('Inactivo', 'Inactivo')], validators=[DataRequired()])

    # Campo para el codigo de usuario
    codigoUsuario = StringField('Código de Usuario', validators=[DataRequired(), Length(max=255)])

    #imagen = FileField('Imagen')
