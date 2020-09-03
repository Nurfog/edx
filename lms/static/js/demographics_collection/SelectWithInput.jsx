import React from 'react';

export const SelectWithInput = (props) => {
  const {
    selectName,
    selectId,
    selectValue,
    options,
    inputName,
    inputId,
    inputType,
    inputValue,
    selectOnChange,
    inputOnChange,
    showInput,
    inputOnBlur,
    labelText,
  } = props;
  return (
    <div className="d-flex flex-column">
      <label htmlFor={selectName}>{labelText}</label>
      <select
        className="form-control"
        name={selectName}
        id={selectId}
        onChange={selectOnChange}
        value={selectValue}
      >
        {options}
      </select>
      {showInput &&
        <input
          className="form-control"
          type={inputType}
          name={inputName}
          id={inputId}
          onChange={inputOnChange}
          onBlur={inputOnBlur}
          value={inputValue}
        />
      }
    </div>
  )
}